require "./spec_helper"

describe Secp256k1Zkp do
  # TODO: Write tests

  it "secp256k1_context_create" do
    Secp256k1Zkp::LibSecp256k1.secp256k1_context_create(Secp256k1Zkp::LibSecp256k1::SECP256K1_CONTEXT_ALL).should_not be_nil
  end
end
