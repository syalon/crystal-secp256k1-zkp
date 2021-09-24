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
    sha256("test", raw = false).size.should eq(64)
  end

  it "sha512 size" do
    sha512("test").size.should eq(64)
  end

  it "sha512 hex size" do
    sha512("test", raw = false).size.should eq(128)
  end

  it "rmd160 size" do
    rmd160("test").size.should eq(20)
  end

  it "rmd160 hex size" do
    rmd160("test", raw = false).size.should eq(40)
  end
end
