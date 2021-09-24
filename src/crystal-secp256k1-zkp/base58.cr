require "big"

module Base58
  extend self

  ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  BASE     = ALPHABET.size

  def int_to_base58(int_val : Number) : String
    base58_val = ""
    while int_val >= BASE
      mod = int_val % BASE
      base58_val = ALPHABET[mod.to_big_i, 1] + base58_val
      int_val = (int_val - mod).divmod(BASE).first
    end
    ALPHABET[int_val.to_big_i, 1] + base58_val
  end

  def base58_to_int(base58_val : String) : Number
    int_val = BigInt.new
    base58_val.reverse.split(//).each_with_index do |char, index|
      char_index = ALPHABET.index(char)
      raise ArgumentError.new("Value passed not a valid Base58 String. (#{base58_val})") if char_index.nil?
      int_val += (char_index.to_big_i) * (BASE.to_big_i ** (index.to_big_i))
    end
    int_val
  end

  def bytes_to_base58(binary_val : Bytes, include_leading_zeroes = true) : String
    return int_to_base58(0) if binary_val.empty?

    if include_leading_zeroes
      nzeroes = binary_val.each_with_index { |b, idx| break idx if b != 0 } || binary_val.size - 1
      prefix = ALPHABET[0, 1] * nzeroes
    else
      prefix = ""
    end

    prefix + int_to_base58(binary_val.hexstring.to_i(16))
  end

  def base58_to_bytes(base58_val : String) : Bytes
    nzeroes = base58_val.each_char_with_index { |c, idx| break idx if c != ALPHABET[0, 1] } || base58_val.size - 1
    prefix = nzeroes < 0 ? "" : "00" * nzeroes
    return (prefix + int_to_hex(base58_to_int(base58_val))).hexbytes
  end

  private def int_to_hex(int) : String
    hex = int.to_s(16)
    (hex.size % 2 == 0) ? hex : ("0" + hex)
  end
end
