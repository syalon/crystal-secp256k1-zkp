require "digest"

module Secp256k1Zkp
  module Utility
    def sha256(data, raw = true)
      if raw
        return Digest::SHA256.digest(data)
      else
        return Digest::SHA256.hexdigest(data)
      end
    end

    def sha512(data, raw = true)
      if raw
        return Digest::SHA512.digest(data)
      else
        return Digest::SHA512.hexdigest(data)
      end
    end

    def rmd160(data, raw = true)
      if raw
        return Digest::RMD160.digest(data)
      else
        return Digest::RMD160.hexdigest(data)
      end
    end

    # def hex_encode(data)
    # hexstring
    #   return data.unpack("H*").first.downcase
    # end

    # def hex_decode(data)
    #   return [data].pack("H*")
    # end

    # def base58_encode(str, alphabet = :bitcoin)
    #   Base58.binary_to_base58(str.force_encoding("BINARY"), alphabet)
    # end

    # def base58_decode(base58_str, alphabet = :bitcoin)
    #   Base58.base58_to_binary(base58_str, alphabet)
    # end

  end
end
