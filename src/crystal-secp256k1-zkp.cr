# TODO: Write documentation for `Crystal::Secp256k1::Zkp`
module Crystal::Secp256k1Zkp
  VERSION = "0.1.0"

  # TODO: Put your code here

  # /** Flags to pass to secp256k1_context_create. */
  # define SECP256K1_CONTEXT_VERIFY (1 << 0)
  # define SECP256K1_CONTEXT_SIGN   (1 << 1)
  # define SECP256K1_CONTEXT_COMMIT (1 << 7)
  # define SECP256K1_CONTEXT_RANGEPROOF (1 << 8)

  # 静态链接
  # # -Wl,-Bstatic -lfoo -lbar -Wl,-Bdynamic
  # @[Link(ldflags: "-static -lsecp256k1 -L#{__DIR__}/../secp256k1-zkp -Wl,-Bdynamic")]

  # 动态链接
  @[Link(ldflags: "-L#{__DIR__}/../secp256k1-zkp/.libs -lsecp256k1 -lgmp")]
  lib LibSecp256k1
    fun secp256k1_context_create(flag : Int32) : Void

    fun secp256k1_point_multiply(point : LibC::UChar*, pointlen : LibC::Int*, scalar : LibC::UChar*) : LibC::Int
#   SECP256K1_WARN_UNUSED_RESULT int secp256k1_point_multiply(
#   unsigned char *point,
#   int *pointlen,
#   const unsigned char *scalar
# ) 
  end



end

# point = 0_u8
# pointlen = 0

# Crystal::Secp256k1Zkp::LibSecp256k1.secp256k1_point_multiply(pointerof(point), pointerof(pointlen), pointerof(point))
# puts "done"
