# TODO: Write documentation for `Crystal::Secp256k1::Zkp`
module Crystal::Secp256k1Zkp
  VERSION = "0.1.0"

  # TODO: Put your code here

  @[Link("secp256k1")]
  lib LibSecp256k1
    fun secp256k1_context_create(flag : Int32) : Void
  end
  
end

