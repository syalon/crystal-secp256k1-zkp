require "./spec_helper"

include Secp256k1Zkp::Utility

describe Secp256k1Zkp do
  it "secp256k1_context_create" do
    Secp256k1Zkp::LibSecp256k1.secp256k1_context_create(Secp256k1Zkp::LibSecp256k1::SECP256K1_CONTEXT_ALL).should_not be_nil
  end

  it "sha256 size" do
    sha256("test").size.should eq(32)
  end

  it "sha256 hex size" do
    sha256_hex("test").size.should eq(64)
  end

  it "sha512 size" do
    sha512("test").size.should eq(64)
  end

  it "sha512 hex size" do
    sha512_hex("test").size.should eq(128)
  end

  it "rmd160 size" do
    rmd160("test").size.should eq(20)
  end

  it "rmd160 hex size" do
    rmd160_hex("test").size.should eq(40)
  end

  it "string hex_encode" do
    hex_encode("abcdABCD").should eq("6162636441424344")
  end

  it "slice hex_encode" do
    hex_encode(Bytes[12, 192]).should eq("0cc0")
  end

  it "string hex_decode" do
    hex_decode("0cc0").should eq(Bytes[12, 192])
  end

  it "hex_encode && hex_decode" do
    hex_decode(hex_encode(Bytes[12, 192])).should eq(Bytes[12, 192])
  end

  it "hex_encode && hex_decode 2" do
    String.new(hex_decode(hex_encode("abcdABCD"))).should eq("abcdABCD")
  end

  it "base58" do
    base58_decode(base58_encode(Bytes[1, 2, 3, 4])).should eq(Bytes[1, 2, 3, 4])
    base58_decode(base58_encode(Bytes[100, 101])).should eq(Bytes[100, 101])
  end

  it "publick key" do
    pubkey = Secp256k1Zkp::PublicKey.from_wif("BTS6ictwisU3gYaq27t3Em1TZDbzfaJeNf2SAXq9S77KgQHhxaj7C")
    pubkey.to_wif.should eq("BTS6ictwisU3gYaq27t3Em1TZDbzfaJeNf2SAXq9S77KgQHhxaj7C")

    pubkey.to_blockchain_address
  end

  it "private key" do
    p! Secp256k1Zkp::PrivateKey.random.to_wif
    p! Secp256k1Zkp::PrivateKey.from_account_and_password("committee-account", "123456").to_wif

    prikey = Secp256k1Zkp::PrivateKey.from_wif("5Kg7Szeo9LHUrPW4JQRC5bckgoGVADiVgeqeXufWWGea9tMpGfX")
    prikey.to_wif.should eq("5Kg7Szeo9LHUrPW4JQRC5bckgoGVADiVgeqeXufWWGea9tMpGfX")
  end

  it "sign" do
    prikey = Secp256k1Zkp::PrivateKey.random
    message_digest = sha256("abc")
    ctx = Secp256k1Zkp::Context.new
    signature = ctx.sign_compact(message_digest, prikey, false)
    p! signature
    signature.should_not eq(nil)
  end
end
