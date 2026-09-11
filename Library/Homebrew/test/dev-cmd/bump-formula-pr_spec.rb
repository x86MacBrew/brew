# typed: true
# frozen_string_literal: true

require "cmd/shared_examples/args_parse"
require "dev-cmd/bump-formula-pr"
require "utils/pypi"

RSpec.describe Homebrew::DevCmd::BumpFormulaPr do
  subject(:bump_formula_pr) { described_class.new(["test"]) }

  let(:f) do
    formula("test") do
      T.bind(self, T.class_of(Formula))
      url "https://brew.sh/test-1.2.3.tgz"
    end
  end

  it_behaves_like "parseable arguments"

  it "updates a Formula without creating a pull request", :integration_test do
    formula_path = setup_test_formula "testball"
    CoreTap.instance.path.cd do
      system "git", "init"
      system "git", "remote", "add", "origin", "https://github.com/Homebrew/homebrew-core"
    end
    tarball = TEST_FIXTURE_DIR/"tarballs/testball2-0.1.tbz"

    expect do
      brew "bump-formula-pr", "--write-only", "--no-audit", "--version=0.2",
           "--url=file://#{tarball}", "--sha256=#{tarball.sha256}", "testball"
    end.to be_a_success
    expect(formula_path.read).to include("version \"0.2\"")
  end

  describe "#run" do
    it "updates a formula disabled only on the current arch" do
      formula_path = CoreTap.instance.new_formula_path("test")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Test < Formula
          url "https://brew.sh/test-1.2.3.tgz"
          sha256 "#{"a" * 64}"

          on_#{Hardware::CPU.arm? ? "arm" : "intel"} do
            disable! date: "2020-01-01", because: :unmaintained
          end
        end
      RUBY
      formula = Formulary.factory(formula_path)
      command = described_class.new([
        "--write-only", "--no-audit", "--url=https://brew.sh/test-1.2.4.tgz", "--sha256=#{"b" * 64}", "test"
      ])

      allow(Utils::GemSetup).to receive(:install_bundler_gems!)
      allow(CoreTap.instance).to receive_messages(allow_bump?: true, git?: true,
                                                  remote_repository: "Homebrew/homebrew-core", install: nil)
      allow(command).to receive_messages(check_new_version: nil, run_audit: false,
                                         update_matching_version_resources!: {})
      allow(PyPI).to receive(:update_python_resources!)
      allow(command.args.named).to receive(:to_formulae).and_return([formula])
      allow(Formula).to receive(:[]).with("test").and_return(formula)

      command.run

      expect(formula_path.read).to include('url "https://brew.sh/test-1.2.4.tgz"')
    end

    it "updates a formula disabled only on the current OS" do
      formula_path = CoreTap.instance.new_formula_path("test")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Test < Formula
          url "https://brew.sh/test-1.2.3.tgz"
          sha256 "#{"a" * 64}"

          on_#{OS.mac? ? "macos" : "linux"} do
            disable! date: "2020-01-01", because: :unmaintained
          end
        end
      RUBY
      formula = Formulary.factory(formula_path)
      command = described_class.new([
        "--write-only", "--no-audit", "--url=https://brew.sh/test-1.2.4.tgz", "--sha256=#{"b" * 64}", "test"
      ])

      allow(Utils::GemSetup).to receive(:install_bundler_gems!)
      allow(CoreTap.instance).to receive_messages(allow_bump?: true, git?: true,
                                                  remote_repository: "Homebrew/homebrew-core", install: nil)
      allow(command).to receive_messages(check_new_version: nil, run_audit: false,
                                         update_matching_version_resources!: {})
      allow(PyPI).to receive(:update_python_resources!)
      allow(command.args.named).to receive(:to_formulae).and_return([formula])
      allow(Formula).to receive(:[]).with("test").and_return(formula)

      command.run

      expect(formula_path.read).to include('url "https://brew.sh/test-1.2.4.tgz"')
    end

    it "adds updated mirrors as string literals" do
      formula_path = CoreTap.instance.new_formula_path("couchdb")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Couchdb < Formula
          url "https://www.apache.org/dyn/closer.lua?path=couchdb/source/3.5.1/apache-couchdb-3.5.1.tar.gz"
          mirror "https://archive.apache.org/dist/couchdb/source/3.5.1/apache-couchdb-3.5.1.tar.gz"
          sha256 "#{"a" * 64}"
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("couchdb", formula_path, formula_path.read)

      resource_path = mktmpdir/"apache-couchdb-3.5.2.tar.gz"
      resource_path.write("couchdb")
      updated_mirror = "https://archive.apache.org/dist/couchdb/source/3.5.2/apache-couchdb-3.5.2.tar.gz"
      command = described_class.new(["--write-only", "--no-audit", "--version=3.5.2", "couchdb"])

      allow(Utils::GemSetup).to receive(:install_bundler_gems!)
      allow(CoreTap.instance).to receive_messages(allow_bump?: true, git?: true,
                                                  remote_repository: "Homebrew/homebrew-core")
      allow(command).to receive(:check_new_version)
      allow(command).to receive(:fetch_resource_and_forced_version).and_return([resource_path, false])
      allow(command).to receive_messages(run_audit: false, update_matching_version_resources!: {})
      allow(PyPI).to receive(:update_python_resources!)
      allow(Utils::Tar).to receive(:validate_file).with(resource_path)
      allow(command.args.named).to receive(:to_formulae).and_return([formula])
      allow(Formula).to receive(:[]).with("couchdb").and_return(formula)
      expect_any_instance_of(Utils::AST::FormulaAST)
        .to receive(:add_stable_stanzas_after) do |formula_ast, name, stanzas|
        expect(name).to eq(:url)
        expect(stanzas).to include([:mirror, "mirror #{updated_mirror.inspect}"])
        formula_ast.add_stanzas_after(name, stanzas, parent: formula_ast.stanza(:stable, type: :block_call))
      end

      command.run

      expect(formula_path.read).to include "  mirror #{updated_mirror.inspect}\n  " \
                                           "sha256 #{resource_path.sha256.inspect}\n"
    end

    it "adds a forced version as a string literal" do
      # An upstream version string shaped like a `version` stanza would otherwise
      # be spliced into the formula as Ruby source rather than as data. The
      # interpolation is escaped, and inert if it were ever evaluated.
      payload = "version \"1.0\#{RUBY_VERSION}\""
      formula_path = CoreTap.instance.new_formula_path("versionball")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Versionball < Formula
          url "https://brew.sh/versionball-1.0.tar.gz"
          sha256 "#{"a" * 64}"
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("versionball", formula_path, formula_path.read)

      resource_path = mktmpdir/"versionball-2.0.tar.gz"
      resource_path.write("versionball")
      command = described_class.new(["--write-only", "--no-audit", "--version=#{payload}", "versionball"])

      allow(Utils::GemSetup).to receive(:install_bundler_gems!)
      allow(CoreTap.instance).to receive_messages(allow_bump?: true, git?: true,
                                                  remote_repository: "Homebrew/homebrew-core")
      allow(command).to receive(:check_new_version)
      allow(command).to receive(:fetch_resource_and_forced_version).and_return([resource_path, true])
      allow(command).to receive_messages(run_audit: false, update_matching_version_resources!: {})
      allow(PyPI).to receive(:update_python_resources!)
      allow(Utils::Tar).to receive(:validate_file).with(resource_path)
      allow(command.args.named).to receive(:to_formulae).and_return([formula])
      allow(Formula).to receive(:[]).with("versionball").and_return(formula)

      expect_any_instance_of(Utils::AST::FormulaAST)
        .to receive(:add_stable_stanzas_after) do |_formula_ast, name, stanzas|
        expect(name).to eq(:url)
        expect(stanzas).to include([:version, "version #{payload.inspect}"])
      end

      # Substituting the version into the URL makes the formula invalid, so the
      # run cannot finish; this example covers how the stanza value is rendered.
      expect { command.run }.to raise_error(FormulaValidationError)
    end
  end

  describe "::check_throttle" do
    let(:tap) { Tap.fetch("test", "tap") }

    let(:f_throttle) do
      formula("throttle-test") do
        T.bind(self, T.class_of(Formula))
        url "https://brew.sh/test-1.2.3.tgz"

        livecheck do
          throttle 5
        end
      end
    end

    let(:f_throttle_days) do
      formula("throttle-days-test") do
        T.bind(self, T.class_of(Formula))
        url "https://brew.sh/test-1.2.3.tgz"

        livecheck do
          throttle days: 1
        end
      end
    end

    let(:f_throttle_rate_and_days) do
      formula("throttle-rate-and-days-test") do
        T.bind(self, T.class_of(Formula))
        url "https://brew.sh/test-1.2.3.tgz"

        livecheck do
          throttle 5, days: 1
        end
      end
    end

    let(:throttle_error) { "Error: throttle-test should only be updated every 5 releases on multiples of 5\n" }
    let(:throttle_days_error) { "Error: throttle-days-test should only be updated every 1 day\n" }
    let(:throttle_rate_days_error) do
      "Error: throttle-rate-and-days-test should only be updated every 5 releases on multiples of 5 or 1 day\n"
    end

    context "when formula is not in a tap" do
      it "outputs nothing" do
        allow(f).to receive(:tap).and_return(nil)

        expect { bump_formula_pr.check_throttle(f, "1.2.4") }.not_to output.to_stderr
      end
    end

    context "when a livecheck throttle value isn't present" do
      it "does not throttle" do
        allow(f).to receive(:tap).and_return(tap)

        expect { bump_formula_pr.check_throttle(f, "1.2.4") }.not_to output.to_stderr
      end
    end

    context "when patch version is a multiple of throttle rate" do
      it "does not throttle" do
        allow(f_throttle).to receive(:tap).and_return(tap)

        expect { bump_formula_pr.check_throttle(f_throttle, "1.2.5") }.not_to output.to_stderr
      end
    end

    context "when patch version is not a multiple of throttle rate" do
      it "throttles version" do
        allow(f_throttle).to receive(:tap).and_return(tap)

        expect do
          bump_formula_pr.check_throttle(f_throttle, "1.2.4")
        rescue SystemExit
          nil
        end.to output(throttle_error).to_stderr
      end
    end

    context "when patch version is not a multiple and throttle days are set" do
      before do
        allow(f_throttle_rate_and_days).to receive(:tap).and_return(tap)
      end

      it "throttles version when throttle interval has not elapsed" do
        allow(Homebrew::Livecheck).to receive(:throttle_interval_elapsed?).and_return(false)

        expect do
          bump_formula_pr.check_throttle(f_throttle_rate_and_days, "1.2.4")
        rescue SystemExit
          nil
        end.to output(throttle_rate_days_error).to_stderr
      end

      it "does not throttle when throttle interval has elapsed" do
        allow(Homebrew::Livecheck).to receive(:throttle_interval_elapsed?).and_return(true)

        expect { bump_formula_pr.check_throttle(f_throttle_rate_and_days, "1.2.4") }.not_to output.to_stderr
      end
    end

    context "when only throttle days is set" do
      before do
        allow(f_throttle_days).to receive(:tap).and_return(tap)
      end

      it "throttles version when throttle interval has not elapsed" do
        allow(Homebrew::Livecheck).to receive(:throttle_interval_elapsed?).and_return(false)

        expect do
          bump_formula_pr.check_throttle(f_throttle_days, "1.2.4")
        rescue SystemExit
          next
        end.to output(throttle_days_error).to_stderr
      end

      it "does not throttle when throttle interval has elapsed" do
        allow(Homebrew::Livecheck).to receive(:throttle_interval_elapsed?).and_return(true)

        expect do
          bump_formula_pr.check_throttle(f_throttle_days, "1.2.4")
        end.not_to output.to_stderr
      end
    end
  end

  describe "::update_matching_version_resources!" do
    let(:f) do
      formula("test") do
        T.bind(self, T.class_of(Formula))
        url "https://brew.sh/test-1.2.3.tgz"

        resource "parent" do
          url "https://brew.sh/parent-1.2.3.tar.gz"
          livecheck do
            formula :parent
          end
        end

        resource "no-parent" do
          url "https://brew.sh/no-parent-1.2.3.tar.gz"
        end
      end
    end
    let(:resource) { f.resource("parent") }
    let(:version) { "1.2.4" }

    it "only updates `:parent` resource" do
      expect(bump_formula_pr).to receive(:update_resource_block!).with(f, resource, version).and_return(:success)
      expect(bump_formula_pr.update_matching_version_resources!(f, version:)).to eq({ "parent" => :success })
    end

    it "does not update `:parent` resource if set in `--resource-versions`" do
      resource_versions = { "parent" => { current_version: "1.2.3", latest_version: version } }
      expect(bump_formula_pr).not_to receive(:update_resource_block!)
      expect(bump_formula_pr.update_matching_version_resources!(f, version:, resource_versions:)).to eq({})
    end
  end

  describe "::update_resources!" do
    let(:f) do
      formula("test") do
        T.bind(self, T.class_of(Formula))
        url "https://brew.sh/test-1.0.0.tgz"

        resource "foo" do
          url "https://brew.sh/foo-1.2.3.tar.gz"
        end
      end
    end
    let(:r) { f.resource("foo") }

    it "updates to requested version" do
      version = "2.1.0"
      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: version } }
      expect(bump_formula_pr).to receive(:update_resource_block!).with(f, r, version).and_return(:success)
      expect(bump_formula_pr.update_resources!(f, resource_versions:)).to eq({ "foo" => :success })
    end

    it "adds a forced resource version as a string literal" do
      # As for the formula stanza, a resource version shaped like a `version`
      # stanza would otherwise be spliced in as Ruby source.
      payload = "version \"1.0\#{RUBY_VERSION}\""
      formula_path = CoreTap.instance.new_formula_path("resourceball")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Resourceball < Formula
          url "https://brew.sh/resourceball-1.0.tar.gz"

          resource "foo" do
            url "https://brew.sh/foo-1.2.3.tar.gz"
            sha256 "#{"b" * 64}"
          end
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("resourceball", formula_path, formula_path.read)

      resource_path = mktmpdir/"foo.tar.gz"
      resource_path.write("foo")
      allow(bump_formula_pr).to receive(:fetch_resource_and_forced_version).and_return([resource_path, true])
      allow(Utils::Tar).to receive(:validate_file).with(resource_path)

      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: payload } }
      bump_formula_pr.update_resources!(formula, resource_versions:)

      expect(formula_path.read).to include("version #{payload.inspect}")
    end

    it "updates tag and revision for a git resource" do
      formula_path = CoreTap.instance.new_formula_path("gitresourceball")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Gitresourceball < Formula
          url "https://brew.sh/gitresourceball-1.0.tar.gz"

          resource "foo" do
            url "https://brew.sh/foo.git",
                tag:      "v1.2.3",
                revision: "#{"a" * 40}"
          end
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("gitresourceball", formula_path, formula_path.read)

      allow(bump_formula_pr).to receive(:fetch_resource_and_forced_version).and_return([mktmpdir, false])
      allow(Utils).to receive(:popen_read).and_return("#{"b" * 40}\n")

      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: "2.0.0" } }

      expect(bump_formula_pr.update_resources!(formula, resource_versions:)).to eq({ "foo" => :success })
      expect(formula_path.read).to include('tag:      "v2.0.0"')
      expect(formula_path.read).to include("revision: \"#{"b" * 40}\"")
    end

    it "updates revision for a git resource without a tag" do
      old_revision = "b" * 40
      new_revision = "a" * 40
      formula_path = CoreTap.instance.new_formula_path("gitresourceball")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Gitresourceball < Formula
          url "https://brew.sh/gitresourceball-1.0.tar.gz"

          resource "foo" do
            url "https://brew.sh/foo.git",
                revision: "#{old_revision}"
            version "#{old_revision}"
          end
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("gitresourceball", formula_path, formula_path.read)

      resource = Resource.new("foo")
      allow(Resource).to receive(:new).with("foo").and_return(resource)
      allow(Resource).to receive(:new).with("gitresourceball").and_return(instance_double(Resource))
      allow(resource).to receive(:fetch).and_return(mktmpdir)

      resource_versions = { "foo" => { current_version: old_revision, latest_version: new_revision } }

      expect(bump_formula_pr.update_resources!(formula, resource_versions:)).to eq({ "foo" => :success })
      expect(formula_path.read).to include("revision: \"#{new_revision}\"", "version \"#{new_revision}\"")
    end

    it "updates the URL for a non-git resource carrying a tag" do
      formula_path = CoreTap.instance.new_formula_path("tarballwithtag")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Tarballwithtag < Formula
          url "https://brew.sh/tarballwithtag-1.0.tar.gz"

          resource "foo" do
            url "https://brew.sh/foo-1.2.3.tar.gz", tag: "v1.2.3"
            sha256 "#{"a" * 64}"
          end
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("tarballwithtag", formula_path, formula_path.read)

      resource_path = mktmpdir/"foo-2.0.0.tar.gz"
      resource_path.write "test"
      allow(bump_formula_pr).to receive(:fetch_resource_and_forced_version).and_return([resource_path, false])
      allow(Utils::Tar).to receive(:validate_file).with(resource_path)

      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: "2.0.0" } }

      expect(bump_formula_pr.update_resources!(formula, resource_versions:)).to eq({ "foo" => :success })
      expect(formula_path.read).to include("https://brew.sh/foo-2.0.0.tar.gz")
      expect(formula_path.read).to include(%Q(sha256 "#{resource_path.sha256}"))
    end

    it "reports git resources whose tag does not change" do
      formula_path = CoreTap.instance.new_formula_path("sametagball")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Sametagball < Formula
          url "https://brew.sh/sametagball-1.0.tar.gz"

          resource "foo" do
            url "https://brew.sh/foo.git",
                tag:      "stable",
                revision: "#{"a" * 40}"
          end
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("sametagball", formula_path, formula_path.read)

      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: "2.0.0" } }

      expect(bump_formula_pr.update_resources!(formula, resource_versions:)).to eq({ "foo" => :tag_unchanged })
    end

    it "reports git resources where new revision cannot be detected from new version" do
      formula_path = CoreTap.instance.new_formula_path("sametagball")
      formula_path.dirname.mkpath
      formula_path.write <<~RUBY
        class Sametagball < Formula
          url "https://brew.sh/sametagball-1.0.tar.gz"

          resource "foo" do
            url "https://brew.sh/foo.git",
                revision: "#{"a" * 40}"
            version "1.2.3"
          end
        end
      RUBY
      CoreTap.instance.clear_cache
      Formulary.clear_cache
      Formula.clear_cache
      formula = Formulary.from_contents("sametagball", formula_path, formula_path.read)

      resource = Resource.new("foo")
      allow(Resource).to receive(:new).with("foo").and_return(resource)
      allow(Resource).to receive(:new).with("sametagball").and_return(instance_double(Resource))
      allow(resource).to receive(:fetch).and_return(mktmpdir)

      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: "2.0.0" } }

      expect(bump_formula_pr.update_resources!(formula, resource_versions:)).to eq({ "foo" => :revision_unresolved })
    end

    it "downgrades to requested version" do
      version = "0.1.2"
      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: version } }
      expect(bump_formula_pr).to receive(:update_resource_block!).with(f, r, version).and_return(:success)
      expect(bump_formula_pr.update_resources!(f, resource_versions:)).to eq({ "foo" => :downgraded })
    end

    it "returns update failures" do
      version = "0.1.2"
      resource_versions = { "foo" => { current_version: "1.2.3", latest_version: version } }
      expect(bump_formula_pr).to receive(:update_resource_block!).with(f, r, version).and_return(:url_unchanged)
      expect(bump_formula_pr.update_resources!(f, resource_versions:)).to eq({ "foo" => :url_unchanged })
    end
  end
end
