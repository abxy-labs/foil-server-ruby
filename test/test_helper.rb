require "json"
require "rubygems"
require "pathname"
require "minitest/autorun"
require "foil/server"

module FixtureHelper
  ROOT = Pathname.new(__dir__).join("..").expand_path

  def load_fixture(relative_path)
    JSON.parse(ROOT.join("spec", "fixtures", relative_path).read, symbolize_names: true)
  end
end

class Minitest::Test
  include FixtureHelper

  def require_crypto_support!
    return if Foil::Server::CryptoSupport.supported_runtime?

    skip(Foil::Server::CryptoSupport.unsupported_runtime_message)
  end
end
