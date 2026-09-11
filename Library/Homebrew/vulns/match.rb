# typed: strict
# frozen_string_literal: true

require "utils/output"

require "formula_versions"
require "vulns/advisory_overrides"
require "vulns/cpan_sec"
require "vulns/history"
require "vulns/identify"
require "vulns/osv"
require "vulns/osv_export"
require "vulns/repology"
require "vulns/vulnerability"

module Homebrew
  module Vulns
    # Authoring-time advisory matcher. For a given {Formula} it derives every
    # OSV.dev query key it can (forge repository, language-registry package for
    # the primary URL and each `resource`, distro source packages via
    # {Repology}, CPAN distribution via {CPANSec}), issues *versionless* queries
    # against each, resolves distro advisories to their upstream CVEs, and
    # evaluates each hit's affected range against the version we ship.
    #
    # Runs in `Homebrew/advisory-database` CI and the homebrew-core PR bot to
    # produce candidate `BREW-*` records for human review; never on a user's
    # machine, so request volume is traded for recall and every candidate
    # carries a strategy/confidence label for the reviewer.
    class Match
      include Utils::Output::Mixin

      # Descending precision. When several strategies reach the same CVE the
      # highest is reported as the hit's primary strategy; the rest are kept as
      # supporting evidence.
      STRATEGY_PRECISION = T.let(
        { git: 4, registry: 3, cpansa: 2, distro: 1 }.freeze,
        T::Hash[Symbol, Integer],
      )

      # Recorded in `database_specific.confidence` for the reviewer.
      CONFIDENCE = T.let(
        { git: "high", registry: "high", cpansa: "medium", distro: "low" }.freeze,
        T::Hash[Symbol, String],
      )

      Identity = Struct.new(
        :git_repo, :git_tag, :primary_package, :resource_packages, :distro_packages,
        keyword_init: true
      ) do
        sig { returns(T::Boolean) }
        def identifiable?
          !git_repo.nil? || !primary_package.nil? || resource_packages.any? || distro_packages.any?
        end
      end

      # `ecosystem`/`name` are the OSV `package` fields queried, so a hit's
      # `affected[]` entry can be matched back to this evidence.
      # `subject_version` is the version to evaluate that entry's ranges
      # against: the formula version for the primary source, the pinned
      # resource version for a resource, `nil` for distro (whose versions are
      # not comparable to ours). `advisory` carries the CPANSA record for
      # `:cpansa` evidence so its constraint strings survive to
      # {#range_status}. `source_record` is the {Vulnerability} this evidence
      # was matched against (attached at hit-construction time), so after
      # {#dedup_by_aliases} merges hits each evidence still points at the record
      # whose `affected[]` it should be checked against.
      Evidence = Struct.new(:strategy, :ecosystem, :name, :subject_version, :key, :resource,
                            :advisory, :source_record, keyword_init: true) do
        sig { params(record: Vulnerability).returns(T.untyped) }
        def with_source(record)
          source_record ? self : self.class.new(**to_h, source_record: record).freeze
        end
      end

      class Hit
        sig { returns(Vulnerability) }
        attr_reader :vulnerability

        sig { returns(T::Array[Evidence]) }
        attr_reader :evidence

        sig { params(vulnerability: Vulnerability, evidence: T::Array[Evidence]).void }
        def initialize(vulnerability:, evidence:)
          raise ArgumentError, "Hit requires at least one Evidence" if evidence.empty?

          @vulnerability = vulnerability
          @evidence = T.let(
            evidence.map { |e| e.with_source(vulnerability) }
                    .sort_by { |e| -STRATEGY_PRECISION.fetch(e.strategy) }.freeze,
            T::Array[Evidence],
          )
        end

        sig { returns(Evidence) }
        def primary_evidence
          evidence.fetch(0)
        end

        sig { returns(Symbol) }
        def strategy
          primary_evidence.strategy
        end

        sig { returns(T.nilable(String)) }
        def resource
          primary_evidence.resource
        end

        sig { returns(String) }
        def canonical_id
          vulnerability.cve_ids.min || vulnerability.id
        end

        sig { returns(T::Array[String]) }
        def identifiers
          evidence.flat_map { |item| item.source_record&.identifiers || [] }
                  .prepend(*vulnerability.identifiers)
                  .uniq
        end
      end

      sig {
        params(repology: T.nilable(Repology), cpan_sec: T.nilable(CPANSec),
               overrides: T.nilable(AdvisoryOverrides), bulk: T::Boolean).void
      }
      def initialize(repology: nil, cpan_sec: nil, overrides: nil, bulk: false)
        @repology = repology
        @cpan_sec = cpan_sec
        @overrides = overrides
        @bulk = bulk
        @vuln_cache = T.let({}, T::Hash[String, T.nilable(Vulnerability)])
        @history = T.let(History.new, History)
      end

      sig { returns(Repology) }
      def repology
        @repology ||= Repology.load
      end

      sig { returns(CPANSec) }
      def cpan_sec
        @cpan_sec ||= CPANSec.load
      end

      sig { params(formula: Formula).returns(Identity) }
      def identify(formula)
        stable = formula.stable
        stable_url = stable&.url
        Identity.new(
          git_repo:          Identify.repo_url(stable_url, formula.head&.url, formula.homepage),
          git_tag:           Identify.tag(stable_url) || stable&.specs&.dig(:tag) || stable&.version&.to_s,
          primary_package:   primary_registry_package(formula),
          resource_packages: formula.resources.filter_map do |r|
            pkg = Identify.registry_package(r.url)
            [r.name, pkg] if pkg
          end.to_h.freeze,
          distro_packages:   distro_packages_for(formula.name),
        ).freeze
      end

      # Return the formula's source-derived registry package, unless a reviewed
      # override supplies an identity for formulae built from non-registry URLs.
      # Historical conflicts are uncheckable so one stale override cannot abort
      # matching every formula.
      sig {
        params(formula: Formula, strict: T::Boolean).returns(T.nilable(Identify::RegistryPackage))
      }
      def primary_registry_package(formula, strict: true)
        derived = Identify.registry_package(formula.stable&.url)
        override = @overrides&.registry_package_override(formula.name)
        return derived unless override

        if derived
          if derived.ecosystem != override.ecosystem || derived.name != override.name
            raise AdvisoryOverrides::Error, "#{formula.name}.registry_package conflicts with its source URL" if strict

            return
          end
          return derived
        end

        version = formula.stable&.version&.to_s
        return if version.nil?

        Identify.registry_package_for(ecosystem: override.ecosystem, name: override.name, version:)
      end

      # Returns one {Hit} per distinct vulnerability reached by any strategy,
      # grouped by its connected id/alias family. Distro-ecosystem records are
      # resolved to their `upstream` CVE(s), so multi-CVE advisories split into
      # per-CVE hits and collapse onto the same CVE reached via GIT/registry.
      # All queries are versionless so historic bump-fixed advisories are returned;
      # {#range_status} evaluates each hit against the shipped version.
      sig { params(formula: Formula).returns(T::Array[Hit]) }
      def advisories_for(formula)
        result = T.let([], T::Array[Hit])
        each_advisory_batch([formula]) { |_, hits| result = hits }
        result
      end

      BULK_CHUNK = 200
      private_constant :BULK_CHUNK

      # Bulk form of {#advisories_for}: builds the labelled queries for a chunk
      # of formulae at once, sends them through a single {OSV.query_batch}
      # (which itself slices at `BATCH_SIZE`), then yields `(formula, hits)` in
      # input order. Per-formula query counts vary widely (one distro entry per
      # ecosystem×srcname), so chunking bounds memory without accumulating the
      # whole tap's queries or records; the `@vuln_cache` still spans chunks.
      sig {
        params(formulae: T::Enumerable[Formula],
               _blk:     T.proc.params(formula: Formula, hits: T::Array[Hit]).void).void
      }
      def each_advisory_batch(formulae, &_blk)
        formulae.each_slice(BULK_CHUNK) do |chunk|
          identities = T.let({}, T::Hash[Formula, Identity])
          chunk.each do |formula|
            next if @overrides&.skip_formula?(formula.name)

            identities[formula] = identify(formula)
          end
          labelled = T.let([], T::Array[[OSV::Package, [Formula, Evidence]]])
          identities.each do |f, identity|
            next unless identity.identifiable?

            build_osv_queries(identity, f.version.to_s).each do |query, evidence|
              labelled << [query, [f, evidence]]
            end
          end

          by_formula = T.let({}, T::Hash[Formula, T::Hash[String, T::Array[Evidence]]])
          if labelled.any?
            OSV.query_batch(labelled.map(&:first)).each_with_index do |stubs, i|
              formula, evidence = labelled.fetch(i).last
              id_evidence = by_formula[formula] ||= {}
              stubs.each { |stub| (id_evidence[stub.fetch("id")] ||= []) << evidence }
            end
          end

          prefetch_vulnerabilities(by_formula.each_value.flat_map(&:keys))

          chunk.each do |f|
            identity = identities[f]
            next yield f, [] unless identity&.identifiable?

            yield f, hits_from(by_formula[f] || {}, identity)
          end
        end
      end

      sig {
        params(id_evidence: T::Hash[String, T::Array[Evidence]], identity: Identity).returns(T::Array[Hit])
      }
      def hits_from(id_evidence, identity)
        hits = resolve_upstream(id_evidence, identity)
        cpan_evidence(identity).each do |ev|
          cpan_sec.advisories_for(ev.name).each do |adv|
            annotated = Evidence.new(**ev.to_h, advisory: adv).freeze
            if adv.cves.any?
              adv.cves.each do |cve|
                record = fetch_vulnerability(cve) || cpansa_vulnerability(adv, id: cve)
                hits << Hit.new(vulnerability: record, evidence: [annotated])
              end
            else
              hits << Hit.new(vulnerability: cpansa_vulnerability(adv, id: adv.id.to_s),
                              evidence:      [annotated])
            end
          end
        end
        dedup_by_aliases(hits)
      end

      # Synthesise a {Vulnerability} for a CPANSA advisory when OSV has no
      # record. `id` is scoped to the single CVE (or CPANSA id) being handled
      # so a multi-CVE advisory whose CVEs are absent from OSV yields distinct
      # records instead of collapsing under the lowest CVE in dedup.
      sig { params(adv: CPANSec::Advisory, id: String).returns(Vulnerability) }
      def cpansa_vulnerability(adv, id:)
        summary = adv.description.to_s.lines.first&.strip
        Vulnerability.new({
          "id"         => id,
          "summary"    => summary,
          "details"    => adv.description,
          "references" => adv.references.map { |u| { "type" => "WEB", "url" => u } },
        }.compact)
      end

      sig {
        params(identity: Identity, formula_version: String).returns(T::Array[[OSV::Package, Evidence]])
      }
      def build_osv_queries(identity, formula_version)
        queries = T.let([], T::Array[[OSV::Package, Evidence]])

        if (repo = identity.git_repo)
          queries << [{ ecosystem: "GIT", name: repo, version: nil },
                      Evidence.new(strategy: :git, ecosystem: "GIT", name: repo,
                                   subject_version: identity.git_tag || formula_version,
                                   key: repo).freeze]
        end

        if (pkg = identity.primary_package) && pkg.ecosystem != "CPAN"
          queries << [{ ecosystem: pkg.ecosystem, name: pkg.name, version: nil },
                      Evidence.new(strategy: :registry, ecosystem: pkg.ecosystem, name: pkg.name,
                                   subject_version: pkg.version, key: pkg.purl).freeze]
        end

        identity.resource_packages.each do |resource, pkg|
          next if pkg.ecosystem == "CPAN"

          queries << [{ ecosystem: pkg.ecosystem, name: pkg.name, version: nil },
                      Evidence.new(strategy: :registry, ecosystem: pkg.ecosystem, name: pkg.name,
                                   subject_version: pkg.version, key: pkg.purl, resource:).freeze]
        end

        identity.distro_packages.each do |ecosystem, srcnames|
          srcnames.each do |srcname|
            queries << [{ ecosystem:, name: srcname, version: nil },
                        Evidence.new(strategy: :distro, ecosystem:, name: srcname,
                                     key: "#{ecosystem}/#{srcname}").freeze]
          end
        end

        queries
      end

      sig { params(identity: Identity).returns(T::Array[Evidence]) }
      def cpan_evidence(identity)
        result = T.let([], T::Array[Evidence])
        primary = identity.primary_package
        if primary&.ecosystem == "CPAN"
          result << Evidence.new(strategy: :cpansa, ecosystem: "CPAN", name: primary.name,
                                 subject_version: primary.version, key: primary.purl)
        end
        identity.resource_packages.each do |resource, pkg|
          next if pkg.ecosystem != "CPAN"

          result << Evidence.new(strategy: :cpansa, ecosystem: "CPAN", name: pkg.name,
                                 subject_version: pkg.version, key: pkg.purl, resource:)
        end
        result
      end

      CVE_ID = /\ACVE-\d{4}-\d+\z/
      private_constant :CVE_ID

      MAX_UPSTREAM_HOPS = 5
      private_constant :MAX_UPSTREAM_HOPS

      # Turn `id => [Evidence, ...]` into `[Hit, ...]`, resolving each record to
      # the CVE(s) it derives from. `upstream` is walked transitively with a
      # per-walk visited set (chains like `USN -> UBUNTU-CVE-* -> CVE-*` occur
      # in practice). `related` links to different vulnerabilities per the OSV
      # schema and is only consulted for its bare CVE ids when `upstream` is
      # empty (AlmaLinux ALSA records use it that way). A record that is
      # already a CVE by id or alias, or that reaches no CVE within the hop
      # budget, is kept as-is. Each resolved hit gains synthesised evidence
      # pointing at our own identity so {#range_status} can check the CVE
      # record's `affected[]` against our version.
      sig {
        params(id_evidence: T::Hash[String, T::Array[Evidence]], identity: Identity)
          .returns(T::Array[Hit])
      }
      def resolve_upstream(id_evidence, identity)
        own = own_evidence(identity)
        hits = T.let([], T::Array[Hit])

        id_evidence.each do |id, evidence|
          record = fetch_vulnerability(id)
          next if record.nil?

          resolved = resolve_to_cves(record, Set[id], MAX_UPSTREAM_HOPS)
          if resolved.empty?
            hits << Hit.new(vulnerability: record, evidence:)
            next
          end

          resolved.each do |cve_record|
            ev = cve_record.equal?(record) ? evidence : evidence + own
            hits << Hit.new(vulnerability: cve_record, evidence: ev)
          end
        end

        hits
      end

      # AlmaLinux ALSA-* records list their source CVEs in `related` rather than
      # `upstream`. That is a data-source quirk; per the OSV schema `related`
      # otherwise names *different* vulnerabilities and must not be traversed.
      RELATED_AS_UPSTREAM_PREFIX = "ALSA-"
      private_constant :RELATED_AS_UPSTREAM_PREFIX

      # Returns the set of CVE records `record` derives from. `[record]` if it
      # is one already; `[]` if the walk exhausts without reaching a CVE (the
      # caller then keeps `record` itself as a low-confidence hit).
      sig {
        params(record: Vulnerability, seen: T::Set[String], budget: Integer)
          .returns(T::Array[Vulnerability])
      }
      def resolve_to_cves(record, seen, budget)
        return [record] if record.cve_ids.any?
        return [] if budget.zero?

        follow = record.upstream.presence
        follow ||= record.related.grep(CVE_ID) if record.id.start_with?(RELATED_AS_UPSTREAM_PREFIX)
        Array(follow).uniq.flat_map do |ref|
          next [] unless seen.add?(ref)

          upstream = fetch_vulnerability(ref)
          upstream ? resolve_to_cves(upstream, seen, budget - 1) : []
        end.uniq(&:id)
      end

      # Evidence rows pointing at our own identity keys (git repo, primary
      # registry package) with the formula/package version as subject. Attached
      # to distro-resolved upstream hits so {#range_status} can evaluate the
      # upstream CVE record's `affected[]` against something comparable.
      sig { params(identity: Identity).returns(T::Array[Evidence]) }
      def own_evidence(identity)
        result = T.let([], T::Array[Evidence])
        if (repo = identity.git_repo)
          result << Evidence.new(strategy: :distro, ecosystem: "GIT", name: repo,
                                 subject_version: identity.git_tag, key: "upstream:#{repo}").freeze
        end
        if (pkg = identity.primary_package)
          result << Evidence.new(strategy: :distro, ecosystem: pkg.ecosystem, name: pkg.name,
                                 subject_version: pkg.version, key: "upstream:#{pkg.purl}").freeze
        end
        result
      end

      # Bulk mode (the `--all` sweep) trusts the published index; only a
      # single-formula run (the PR bot, or an explicit named check) may hit the
      # live Repology API for a formula the index doesn't yet cover.
      sig { params(name: String).returns(Repology::DistroMap) }
      def distro_packages_for(name)
        indexed = repology.distro_packages_for(name)
        return indexed if indexed.any? || @bulk

        Repology.lookup(name)
      rescue CachedFeed::Error => e
        odebug "Repology lookup for #{name} failed: #{e.message}"
        {}
      end

      MAX_VULN_FETCH_THREADS = 15
      private_constant :MAX_VULN_FETCH_THREADS

      # OSV `querybatch` returns id/modified stubs. Warm `@vuln_cache` with the
      # full records for a chunk's stub ids before per-formula processing so
      # {#resolve_upstream} reads mostly from cache.
      sig { params(ids: T::Array[String]).void }
      def prefetch_vulnerabilities(ids)
        missing = ids.uniq.reject { |id| @vuln_cache.key?(id) }
        missing.each_slice(MAX_VULN_FETCH_THREADS) do |slice|
          slice.map { |id| [id, Thread.new { load_vulnerability(id) }] }
               .each { |id, t| @vuln_cache[id] = t.value }
        end
      end

      sig { params(id: String).returns(T.nilable(Vulnerability)) }
      def fetch_vulnerability(id)
        @vuln_cache.fetch(id) { @vuln_cache[id] = load_vulnerability(id) }
      end

      sig { params(id: String).returns(T.nilable(Vulnerability)) }
      def load_vulnerability(id)
        Vulnerability.new(OSV.vulnerability(id))
      rescue OSV::Error => e
        odebug "OSV.vulnerability(#{id}) failed: #{e.message}"
        nil
      end

      sig { params(hits: T::Array[Hit]).returns(T::Array[Hit]) }
      def dedup_by_aliases(hits)
        groups = T.let([], T::Array[T::Array[Hit]])
        pending = hits.dup
        until pending.empty?
          first = pending.shift
          raise ArgumentError, "Cannot start an empty alias group" if first.nil?

          # Evidence provenance can legitimately lead to several vulnerabilities,
          # so only the vulnerability's own identifiers connect hits.
          identifiers = T.let({}, T::Hash[String, T::Boolean])
          first.vulnerability.identifiers.each { |identifier| identifiers[identifier] = true }
          group = T.let([first], T::Array[Hit])
          loop do
            connected, remaining = pending.partition do |hit|
              hit.vulnerability.identifiers.any? { |identifier| identifiers.key?(identifier) }
            end
            break if connected.empty?

            connected.each do |hit|
              hit.vulnerability.identifiers.each { |identifier| identifiers[identifier] = true }
            end
            group.concat(connected)
            pending = remaining
          end
          groups << group
        end

        groups.map do |group|
          next group.fetch(0) if group.one?

          # Members of one alias family usually share a `canonical_id`, so the
          # record id is what actually settles the order for most groups. Rank
          # once so the merged evidence order is fixed too, not just the primary.
          ranked = group.sort_by { |h| [-STRATEGY_PRECISION.fetch(h.strategy), h.canonical_id, h.vulnerability.id] }
          Hit.new(vulnerability: ranked.fetch(0).vulnerability,
                  evidence:      ranked.flat_map(&:evidence).uniq)
        end
      end

      # Evaluate `hit` against every evidence's subject, each against the
      # record that evidence was matched against, and aggregate: `:affected` if
      # any subject is affected (a fixed primary must not hide an affected
      # resource, or vice versa), else unknown if any subject is unresolved,
      # else `:fixed` if any is fixed, else
      # `:not_applicable` only when every comparable subject says so. Returns
      # `[status, evidence]` where `evidence` is the one whose result was
      # chosen (used by {#first_fixed_version} and for the emitted record's
      # resource attribution), or `nil` if no evidence produced a checkable
      # answer.
      sig {
        params(hit: Hit, formula_name: T.nilable(String))
          .returns(T.nilable([Vulnerability::RangeStatus, Evidence]))
      }
      def range_status(hit, formula_name: nil)
        subjects = hit.evidence.reject { |ev| ev.strategy == :distro && ev.subject_version.nil? }
                      .group_by(&:resource).map do |_, evidence|
          results = evidence.filter_map do |ev|
            status = evidence_range_status(ev, ev.subject_version)
            [status, ev] if status
          end
          results.find { |s, _| s.affected? } || results.find { |s, _| s.fixed? } || results.first
        end
        results = subjects.compact
        selected = results.find { |s, _| s.affected? }
        selected ||= results.find { |s, _| s.fixed? } || results.first unless subjects.include?(nil)
        override = @overrides&.advisory_override(formula_name, hit.identifiers) if formula_name
        return selected unless override

        status, evidence = selected ||
                           (results.find { |candidate, _| candidate.state == override.state } if override.state) ||
                           [nil, hit.primary_evidence]
        state = override.state || status&.state
        return selected unless state

        fixed_in = override.fixed_in_overridden ? override.fixed_in : status&.fixed_in
        [Vulnerability::RangeStatus.new(state:, fixed_in:).freeze, evidence]
      end

      sig {
        params(evidence: Evidence, subject_version: T.nilable(String))
          .returns(T.nilable(Vulnerability::RangeStatus))
      }
      def evidence_range_status(evidence, subject_version)
        return if subject_version.nil?

        if evidence.strategy == :cpansa
          adv = evidence.advisory
          CPANSec.range_status(adv, subject_version) if adv
        else
          evidence.source_record&.range_status(evidence.ecosystem, evidence.name, subject_version)
        end
      end

      # Emit a candidate `BREW-*` OSV record for `hit` against `formula`.
      #
      # `first_fixed` is the {PkgVersion} at which Homebrew first shipped a fix
      # (from {#first_fixed_version} or a hand-set value), and
      # `first_introduced` is the first affected Homebrew version (from
      # {#first_introduced_version} or {#first_reintroduced_version}). Otherwise
      # {#range_status} is consulted: `affected? == false` sets
      # `fixed: pkg_version` and `ecosystem_specific.fix: "bump"`;
      # `affected? == true` (or no comparable range) emits no `fixed` event and
      # `fix: null`. As with {OsvExport.record_for}, {OsvExport.merge_existing}
      # preserves on-disk `ranges` on rewrite so a hand-corrected boundary
      # sticks.
      sig {
        params(formula: Formula, hit: Hit, first_fixed: T.nilable(String),
               first_introduced: T.nilable(String), now: Time)
          .returns(T::Hash[Symbol, T.untyped])
      }
      def to_brew_record(formula, hit, first_fixed: nil, first_introduced: nil, now: Time.now.utc)
        vuln = hit.vulnerability
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        status, status_evidence = range_status(hit, formula_name: formula.name)

        fixed = first_fixed
        fixed ||= formula.pkg_version.to_s if status&.fixed?
        events = T.let([{ introduced: first_introduced || "0" }], T::Array[T::Hash[Symbol, String]])
        events << { fixed: } if fixed

        record = T.let({
          schema_version:    OsvExport::SCHEMA_VERSION,
          id:                record_id(formula, hit),
          published:         timestamp,
          modified:          timestamp,
          upstream:          hit.identifiers,
          affected:          [affected_entry(formula, hit, events, fixed, status, status_evidence)],
          database_specific: {
            source:            "matched",
            strategy:          hit.strategy.to_s,
            confidence:        confidence_for(hit, status),
            upstream_evidence: hit.evidence.map { |e| e.to_h.except(:advisory, :source_record).compact }.uniq,
          },
        }, T::Hash[Symbol, T.untyped])

        record[:summary] = vuln.summary if vuln.summary
        record[:details] = vuln.details if vuln.details
        record[:severity] = vuln.severity_entries if vuln.severity_entries.any?
        if (refs = vuln.references).any?
          record[:references] = refs.uniq { |r| [r["type"], URI::RFC2396_PARSER.unescape(r["url"].to_s)] }
        end

        record
      end

      sig { params(formula: Formula, hit: Hit).returns(String) }
      def record_id(formula, hit)
        OsvExport.record_id(formula, hit.canonical_id)
      end

      sig { params(formula: Formula, hit: Hit).returns(T::Array[String]) }
      def record_ids(formula, hit)
        ([record_id(formula, hit)] + hit.identifiers.map { |id| OsvExport.record_id(formula, id) }).uniq
      end

      sig {
        params(hit: Hit, status: T.nilable(Vulnerability::RangeStatus)).returns(String)
      }
      def confidence_for(hit, status)
        base = CONFIDENCE.fetch(hit.strategy)
        return base if status

        # No comparable range: the reviewer must set the boundary by hand.
        (base == "high") ? "medium" : "low"
      end

      sig {
        params(formula: Formula, hit: Hit, events: T::Array[T::Hash[Symbol, String]],
               fixed: T.nilable(String), status: T.nilable(Vulnerability::RangeStatus),
               status_evidence: T.nilable(Evidence))
          .returns(T::Hash[Symbol, T.untyped])
      }
      def affected_entry(formula, hit, events, fixed, status, status_evidence)
        eco = T.let({ fix: fixed ? "bump" : nil }, T::Hash[Symbol, T.nilable(String)])
        eco[:range_state] = status.state.to_s if status
        eco[:upstream_fixed_in] = status.fixed_in if status&.fixed_in
        # Attribute the resource whose subject decided the state, falling back
        # to the highest-precision evidence when nothing was comparable.
        if (resource = status_evidence&.resource || hit.resource)
          eco[:resource] = resource
          eco[:resource_purl] = (status_evidence if status_evidence&.resource)&.key ||
                                hit.evidence.find { |e| e.resource == resource }&.key
        end
        {
          package:            {
            ecosystem: OsvExport::ECOSYSTEM,
            name:      formula.name,
            purl:      OsvExport.purl(formula.name),
          },
          ranges:             [{ type: "ECOSYSTEM", events: }],
          ecosystem_specific: eco,
        }
      end

      # Walk homebrew-core git history (newest first) via {History} and return
      # the `pkg_version` at the oldest revision where the aggregate of every
      # checkable subject is still `:fixed`. Re-running the full per-evidence
      # range check with each revision's subject versions keeps `last_affected`
      # and exclusive-bound semantics intact and stops as soon as any subject
      # (primary or a resource) drops back into `:affected`, so a primary fixed
      # at 2.0 with a resource fixed at 3.0 yields 3.0.
      #
      # Returns:
      # - `nil` when the current aggregate is not `:fixed`.
      # - `:never_affected` when the walk reaches `:not_applicable` (or the
      #   start of the formula's history) without ever seeing `:affected`,
      #   i.e. Homebrew jumped from a version below `introduced` straight past
      #   `fixed` and never shipped an affected build. The caller drops the
      #   candidate rather than emitting `{introduced: "0", fixed: <first>}`.
      # - `:history_unavailable` when the tap is a shallow clone, the formula
      #   has no git history or a revision cannot be loaded or compared, so the
      #   caller can skip the candidate rather than inventing a boundary.
      # - a `pkg_version` String when the walk hits `:affected`.
      sig { params(formula: Formula, hit: Hit).returns(T.nilable(T.any(String, Symbol))) }
      def first_fixed_version(formula, hit)
        return unless range_status(hit, formula_name: formula.name)&.first&.fixed?

        last_fixed = T.let(formula.pkg_version.to_s, String)
        result = @history.walk(formula) do |old|
          aggregate = aggregate_state_at(old, hit)
          case aggregate
          when :fixed
            last_fixed = old.pkg_version.to_s
            nil
          when :affected then last_fixed
          when :not_applicable then :never_affected
          when nil then :history_unavailable
          else raise TypeError, "unexpected historical aggregate: #{aggregate.inspect}"
          end
        end
        result || :never_affected
      end

      # Return the earliest affected `pkg_version` for a new record. Check all
      # history: one interval must cover every affected build and no known
      # non-affected build, including resource changes without a revision bump.
      # Unreadable history and unrepresentable intervals require manual review.
      sig { params(formula: Formula, hit: Hit, first_fixed: T.nilable(String)).returns(T.any(String, Symbol)) }
      def first_introduced_version(formula, hit, first_fixed: nil)
        current_state = aggregate_state_at(formula, hit)
        return :history_unavailable unless [:affected, :fixed].include?(current_state)

        affected_versions = T.let([], T::Array[PkgVersion])
        unaffected_versions = T.let([], T::Array[PkgVersion])
        ((current_state == :affected) ? affected_versions : unaffected_versions) << formula.pkg_version
        result = @history.walk(formula) do |old|
          case aggregate_state_at(old, hit)
          when :affected then affected_versions << old.pkg_version
          when :fixed, :not_applicable then unaffected_versions << old.pkg_version
          else next :history_unavailable
          end
          nil
        end
        return :history_unavailable unless result.nil?

        introduced = affected_versions.min
        return :history_unavailable unless introduced

        fixed = PkgVersion.parse(first_fixed) if first_fixed
        return :history_unavailable if fixed && affected_versions.any? { |version| version >= fixed }
        if unaffected_versions.any? { |version| version >= introduced && (!fixed || version < fixed) }
          return :history_unavailable
        end

        introduced.to_s
      rescue ArgumentError
        :history_unavailable
      end

      # Return the lowest representable formula `pkg_version` in the newest
      # contiguous affected run. This is the `introduced` boundary when a
      # reviewed fixed range becomes affected again after a formula or resource
      # regression, including a run whose version strings move backwards after
      # a `version_scheme` change. After finding the transition, the remaining
      # history is checked so the new interval cannot cover a known
      # non-affected formula version.
      # `:not_reintroduced` means no prior non-affected revision was verified,
      # either because all loadable history remained affected, the tap is a
      # shallow clone, the formula has no git history or a revision could not
      # be loaded or compared safely.
      sig { params(formula: Formula, hit: Hit).returns(T.nilable(T.any(String, Symbol))) }
      def first_reintroduced_version(formula, hit)
        return unless range_status(hit, formula_name: formula.name)&.first&.affected?

        first_affected = T.let(formula.pkg_version.to_s, String)
        transition_found = T.let(false, T::Boolean)
        result = @history.walk(formula) do |old|
          aggregate = aggregate_state_at(old, hit)
          next :not_reintroduced if aggregate.nil?

          pkg_version = old.pkg_version.to_s
          begin
            historical = PkgVersion.parse(pkg_version)
            boundary = PkgVersion.parse(first_affected)
            if transition_found
              next :not_reintroduced if aggregate != :affected && historical >= boundary
            elsif aggregate == :affected
              first_affected = pkg_version if historical < boundary
            else
              next :not_reintroduced if historical >= boundary

              transition_found = true
            end
          rescue ArgumentError
            next :not_reintroduced
          end
          nil
        end
        # Every early result is fail-closed: untrusted history, an uncomparable
        # revision or a known non-affected version above the boundary.
        return :not_reintroduced unless result.nil?

        transition_found ? first_affected : :not_reintroduced
      end

      sig { params(formula: Formula, hit: Hit).returns(T.nilable(Symbol)) }
      def aggregate_state_at(formula, hit)
        results = hit.evidence.filter_map do |ev|
          # Evidence built without a subject_version (distro queries, own-
          # identity rows for a formula with no derivable tag) is deliberately
          # uncheckable and must stay that way at historical revisions too;
          # substituting the historical formula version would compare it
          # against the distro record's distro-versioned range.
          next if ev.subject_version.nil?

          present, subject = subject_version_at(formula, ev)
          # Absence means this formula revision did not ship the vulnerable
          # package. Treat it as fixed for boundary walking so a temporary
          # removal can be the fix boundary while still allowing the walk to
          # find an older affected revision.
          next :fixed unless present
          next :unknown if subject.nil?

          evidence_range_status(ev, subject)&.state || :unknown
        end
        return if results.empty?
        return :affected if results.include?(:affected)
        return if results.include?(:unknown)
        return :fixed if results.include?(:fixed)

        :not_applicable
      end

      # Resolve a historical subject by upstream package identity so resource
      # label changes do not look like removals. The boolean distinguishes a
      # package that was absent (not affected at that revision) from one that
      # was present but had no comparable version (uncheckable).
      sig { params(formula: Formula, evidence: Evidence).returns([T::Boolean, T.nilable(String)]) }
      def subject_version_at(formula, evidence)
        unless evidence.resource
          stable = formula.stable
          stable_url = stable&.url
          if evidence.ecosystem == "GIT"
            repo = Identify.repo_url(stable_url, formula.head&.url, formula.homepage)
            return [true, nil] if repo.nil?
            return [true, nil] if repo != evidence.name

            version = Identify.tag(stable_url) || stable&.specs&.dig(:tag) || stable&.version&.to_s
            return [true, version]
          end

          primary_package = primary_registry_package(formula, strict: false)
          return [true, nil] if primary_package.nil?
          if primary_package.ecosystem != evidence.ecosystem || primary_package.name != evidence.name
            return [false, nil]
          end

          return [true, primary_package.version]
        end

        exact_resource = formula.resources.find { |resource| resource.name == evidence.resource }
        exact_identity_unknown = T.let(false, T::Boolean)
        if exact_resource
          exact_package = Identify.registry_package(exact_resource.url)
          if exact_package.nil?
            # A reused resource label is not enough to prove package identity.
            # Search the remaining resources in case the package was renamed,
            # then leave this revision uncheckable if no identity can be found.
            exact_identity_unknown = true
          elsif exact_package.ecosystem == evidence.ecosystem && exact_package.name == evidence.name
            return [true, exact_package.version]
          end
        end

        formula.resources.each do |resource|
          next if resource.equal?(exact_resource)

          package = Identify.registry_package(resource.url)
          next if package.nil?
          next if package.ecosystem != evidence.ecosystem || package.name != evidence.name

          return [true, package.version]
        end

        return [true, nil] if exact_identity_unknown

        [false, nil]
      end
    end
  end
end
