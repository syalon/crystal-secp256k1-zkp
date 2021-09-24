require "digest"
require "openssl"

# Implements the RMD160 digest algorithm.
class Digest::RMD160 < ::OpenSSL::Digest
  extend ClassMethods

  def initialize
    super("RMD160")
  end

  protected def initialize(ctx : LibCrypto::EVP_MD_CTX)
    super("RMD160", ctx)
  end

  def dup
    self.class.new(dup_ctx)
  end
end
