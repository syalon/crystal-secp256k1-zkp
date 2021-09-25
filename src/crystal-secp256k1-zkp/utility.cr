require "digest"

module Secp256k1Zkp
  module Utility
    def sha256(data)
      return Digest::SHA256.digest(data)
    end

    def sha256_hex(data)
      return Digest::SHA256.hexdigest(data)
    end

    def sha512(data)
      return Digest::SHA512.digest(data)
    end

    def sha512_hex(data)
      return Digest::SHA512.hexdigest(data)
    end

    def rmd160(data)
      return Digest::RMD160.digest(data)
    end

    def rmd160_hex(data)
      return Digest::RMD160.hexdigest(data)
    end

    # => Bytes -> hex string
    # => String -> hex string
    def hex_encode(data)
      return data.to_slice.hexstring
    end

    # => hex string -> Bytes
    def hex_decode(data)
      return data.hexbytes
    end

    def base58_encode(str : Bytes) : String
      return Base58.bytes_to_base58(str)
    end

    def base58_decode(base58_str : String) : Bytes
      return Base58.base58_to_bytes(base58_str)
    end
  end
end
