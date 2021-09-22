# TODO: Write documentation for `Crystal::Secp256k1::Zkp`
module Crystal::Secp256k1Zkp
  VERSION = "0.1.0"

  # TODO: Put your code here

  # 静态链接
  # # -Wl,-Bstatic -lfoo -lbar -Wl,-Bdynamic
  # @[Link(ldflags: "-static -lsecp256k1 -L#{__DIR__}/../secp256k1-zkp -Wl,-Bdynamic")]

  # 动态链接
  @[Link(ldflags: "-L#{__DIR__}/../secp256k1-zkp/.libs -lsecp256k1")]
  lib LibSecp256k1
    fun secp256k1_context_create(flag : Int32) : Void
  end

end

