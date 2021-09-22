require "./spec_helper"

describe Crystal::Secp256k1Zkp do
  # TODO: Write tests

  # it "works" do
  #   false.should eq(true)
  # end

  it "init" do
    puts "here"
    Crystal::Secp256k1Zkp::LibSecp256k1.secp256k1_context_create(0).should eq(true)
  end

end
