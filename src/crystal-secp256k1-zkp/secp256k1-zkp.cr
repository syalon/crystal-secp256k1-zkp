require "./utility"

# TODO: Write documentation for `Secp256k1Zkp`
module Secp256k1Zkp
  VERSION = "0.9.0"

  # 静态链接直接链接指定目录，动态链接忽略。
  @[Link(ldflags: "-L#{__DIR__}/../../secp256k1-zkp/.libs -lsecp256k1 -lgmp")]
  lib LibSecp256k1
    # Flags to pass to secp256k1_context_create.
    SECP256K1_CONTEXT_VERIFY     = (1 << 0)
    SECP256K1_CONTEXT_SIGN       = (1 << 1)
    SECP256K1_CONTEXT_COMMIT     = (1 << 7)
    SECP256K1_CONTEXT_RANGEPROOF = (1 << 8)

    SECP256K1_CONTEXT_ALL = SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_COMMIT | SECP256K1_CONTEXT_RANGEPROOF

    type Secp256k1_context_t_ptr = Void*

    # => LibC::
    # alias Char = UInt8
    # alias UChar = Char
    # alias SChar = Int8
    # alias Short = Int16
    # alias UShort = UInt16
    # alias Int = Int32
    # alias UInt = UInt32
    #   {% if flag?(:win32) || flag?(:i386) || flag?(:arm) %}
    # alias Long = Int32
    # alias ULong = UInt32
    #   {% elsif flag?(:x86_64) || flag?(:aarch64) %}
    # alias Long = Int64
    # alias ULong = UInt64
    #   {% end %}
    # alias LongLong = Int64
    # alias ULongLong = UInt64
    # alias Float = Float32
    # alias Double = Float64

    # /** Create a secp256k1 context object.
    #  *  Returns: a newly created context object.
    #  *  In:      flags: which parts of the context to initialize.
    #  */
    fun secp256k1_context_create(flag : Int32) : Secp256k1_context_t_ptr

    # /** Copies a secp256k1 context object.
    #  *  Returns: a newly created context object.
    #  *  In:      ctx: an existing context to copy
    #  */
    fun secp256k1_context_clone(ctx : Secp256k1_context_t_ptr) : Secp256k1_context_t_ptr

    # /** Destroy a secp256k1 context object.
    #   *  The context pointer may not be used afterwards.
    #   */
    fun secp256k1_context_destroy(ctx : Secp256k1_context_t_ptr) : Void

    # /** Verify an ECDSA signature.
    #  *  Returns: 1: correct signature
    #  *           0: incorrect signature
    #  *          -1: invalid public key
    #  *          -2: invalid signature
    #  * In:       ctx:       a secp256k1 context object, initialized for verification.
    #  *           msg32:     the 32-byte message hash being verified (cannot be NULL)
    #  *           sig:       the signature being verified (cannot be NULL)
    #  *           siglen:    the length of the signature
    #  *           pubkey:    the public key to verify with (cannot be NULL)
    #  *           pubkeylen: the length of pubkey
    #  */
    fun secp256k1_ecdsa_verify(ctx : Secp256k1_context_t_ptr,
                               msg : LibC::UChar*,
                               msg : LibC::UChar*,
                               siglen : Int32,
                               pubkey : LibC::UChar*,
                               pubkeylen : Int32) : Int32

    # /** A pointer to a function to deterministically generate a nonce.
    #  * Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
    #  * In:      msg32:     the 32-byte message hash being verified (will not be NULL)
    #  *          key32:     pointer to a 32-byte secret key (will not be NULL)
    #  *          attempt:   how many iterations we have tried to find a nonce.
    #  *                     This will almost always be 0, but different attempt values
    #  *                     are required to result in a different nonce.
    #  *          data:      Arbitrary data pointer that is passed through.
    #  * Out:     nonce32:   pointer to a 32-byte array to be filled by the function.
    #  * Except for test cases, this function should compute some cryptographic hash of
    #  * the message, the key and the attempt.
    #  */
    alias Secp256k1_nonce_function_t = (LibC::UChar*, LibC::UChar*, LibC::UChar*, UInt32, Void*) -> Int32

    # /** An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
    #  * If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
    #  * extra entropy.
    #  */
    $secp256k1_nonce_function_rfc6979 : Secp256k1_nonce_function_t

    # /** A default safe nonce generation function (currently equal to secp256k1_nonce_function_rfc6979). */
    # $secp256k1_nonce_function_default : Secp256k1_nonce_function_t
    $secp256k1_nonce_function_default : (LibC::UChar*, LibC::UChar*, LibC::UChar*, UInt32, Void*) -> Int32

    # /** Create an ECDSA signature.
    #  *  Returns: 1: signature created
    #  *           0: the nonce generation function failed, the private key was invalid, or there is not
    #  *              enough space in the signature (as indicated by siglen).
    #  *  In:      ctx:    pointer to a context object, initialized for signing (cannot be NULL)
    #  *           msg32:  the 32-byte message hash being signed (cannot be NULL)
    #  *           seckey: pointer to a 32-byte secret key (cannot be NULL)
    #  *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
    #  *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
    #  *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
    #  *  In/Out:  siglen: pointer to an int with the length of sig, which will be updated
    #  *                   to contain the actual signature length (<=72).
    #  *
    #  * The sig always has an s value in the lower half of the range (From 0x1
    #  * to 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
    #  * inclusive), unlike many other implementations.
    #  * With ECDSA a third-party can can forge a second distinct signature
    #  * of the same message given a single initial signature without knowing
    #  * the key by setting s to its additive inverse mod-order, 'flipping' the
    #  * sign of the random point R which is not included in the signature.
    #  * Since the forgery is of the same message this isn't universally
    #  * problematic, but in systems where message malleability or uniqueness
    #  * of signatures is important this can cause issues.  This forgery can be
    #  * blocked by all verifiers forcing signers to use a canonical form. The
    #  * lower-S form reduces the size of signatures slightly on average when
    #  * variable length encodings (such as DER) are used and is cheap to
    #  * verify, making it a good choice. Security of always using lower-S is
    #  * assured because anyone can trivially modify a signature after the
    #  * fact to enforce this property.  Adjusting it inside the signing
    #  * function avoids the need to re-serialize or have curve specific
    #  * constants outside of the library.  By always using a canonical form
    #  * even in applications where it isn't needed it becomes possible to
    #  * impose a requirement later if a need is discovered.
    #  * No other forms of ECDSA malleability are known and none seem likely,
    #  * but there is no formal proof that ECDSA, even with this additional
    #  * restriction, is free of other malleability.  Commonly used serialization
    #  * schemes will also accept various non-unique encodings, so care should
    #  * be taken when this property is required for an application.
    #  */
    fun secp256k1_ecdsa_sign(ctx : Secp256k1_context_t_ptr,
                             msg32 : LibC::UChar*,
                             sig : LibC::UChar*,
                             siglen : Int32*,
                             seckey : LibC::UChar*,
                             noncefp : Secp256k1_nonce_function_t,
                             ndata : Void*) : Int32

    # /** Create a compact ECDSA signature (64 byte + recovery id).
    #  *  Returns: 1: signature created
    #  *           0: the nonce generation function failed, or the secret key was invalid.
    #  *  In:      ctx:    pointer to a context object, initialized for signing (cannot be NULL)
    #  *           msg32:  the 32-byte message hash being signed (cannot be NULL)
    #  *           seckey: pointer to a 32-byte secret key (cannot be NULL)
    #  *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
    #  *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
    #  *  Out:     sig:    pointer to a 64-byte array where the signature will be placed (cannot be NULL)
    #  *                   In case 0 is returned, the returned signature length will be zero.
    #  *           recid:  pointer to an int, which will be updated to contain the recovery id (can be NULL)
    #  */
    fun secp256k1_ecdsa_sign_compact(ctx : Secp256k1_context_t_ptr,
                                     msg32 : LibC::UChar*,
                                     sig64 : LibC::UChar*,
                                     seckey : LibC::UChar*,
                                     noncefp : Secp256k1_nonce_function_t,
                                     ndata : Void*,
                                     recid : Int32*) : Int32

    # /** Recover an ECDSA public key from a compact signature.
    #  *  Returns: 1: public key successfully recovered (which guarantees a correct signature).
    #  *           0: otherwise.
    #  *  In:      ctx:        pointer to a context object, initialized for verification (cannot be NULL)
    #  *           msg32:      the 32-byte message hash assumed to be signed (cannot be NULL)
    #  *           sig64:      signature as 64 byte array (cannot be NULL)
    #  *           compressed: whether to recover a compressed or uncompressed pubkey
    #  *           recid:      the recovery id (0-3, as returned by ecdsa_sign_compact)
    #  *  Out:     pubkey:     pointer to a 33 or 65 byte array to put the pubkey (cannot be NULL)
    #  *           pubkeylen:  pointer to an int that will contain the pubkey length (cannot be NULL)
    #  */
    fun secp256k1_ecdsa_recover_compact(ctx : Secp256k1_context_t_ptr,
                                        msg32 : LibC::UChar*,
                                        sig64 : LibC::UChar*,
                                        pubkey : LibC::UChar*,
                                        pubkeylen : Int32*,
                                        compressed : Int32,
                                        recid : Int32) : Int32

    # /** Do an ellitic curve scalar multiplication in constant time.
    #  *  Returns: 1: exponentiation was successful
    #  *          -1: scalar was zero (cannot serialize output point)
    #  *          -2: scalar overflow
    #  *          -3: invalid input point
    #  *  In:      scalar:   a 32-byte scalar with which to multiple the point
    #  *  In/Out:  point:    pointer to 33 or 65 byte array containing an EC point
    #  *                     which will be updated in place
    #  *           pointlen: length of the point array, which will be updated by
    #  *                     the multiplication
    #  */
    fun secp256k1_point_multiply(point : LibC::UChar*, pointlen : Int32*, scalar : LibC::UChar*) : Int32

    # /** Verify an ECDSA secret key.
    #  *  Returns: 1: secret key is valid
    #  *           0: secret key is invalid
    #  *  In:      ctx: pointer to a context object (cannot be NULL)
    #  *           seckey: pointer to a 32-byte secret key (cannot be NULL)
    #  */
    fun secp256k1_ec_seckey_verify(ctx : Secp256k1_context_t_ptr, seckey : LibC::UChar*) : Int32

    # /** Just validate a public key.
    #  *  Returns: 1: public key is valid
    #  *           0: public key is invalid
    #  *  In:      ctx:       pointer to a context object (cannot be NULL)
    #  *           pubkey:    pointer to a 33-byte or 65-byte public key (cannot be NULL).
    #  *           pubkeylen: length of pubkey
    #  */
    fun secp256k1_ec_pubkey_verify(ctx : Secp256k1_context_t_ptr, pubkey : LibC::UChar*, pubkeylen : Int32) : Int32

    # /** Compute the public key for a secret key.
    #  *  In:     ctx:        pointer to a context object, initialized for signing (cannot be NULL)
    #  *          compressed: whether the computed public key should be compressed
    #  *          seckey:     pointer to a 32-byte private key (cannot be NULL)
    #  *  Out:    pubkey:     pointer to a 33-byte (if compressed) or 65-byte (if uncompressed)
    #  *                      area to store the public key (cannot be NULL)
    #  *          pubkeylen:  pointer to int that will be updated to contains the pubkey's
    #  *                      length (cannot be NULL)
    #  *  Returns: 1: secret was valid, public key stores
    #  *           0: secret was invalid, try again
    #  */
    fun secp256k1_ec_pubkey_create(ctx : Secp256k1_context_t_ptr,
                                   pubkey : LibC::UChar*,
                                   pubkeylen : Int32*,
                                   seckey : LibC::UChar*,
                                   compressed : Int32) : Int32

    # /** Decompress a public key.
    #  * In:     ctx:       pointer to a context object (cannot be NULL)
    #  * In/Out: pubkey:    pointer to a 65-byte array to put the decompressed public key.
    #  *                    It must contain a 33-byte or 65-byte public key already (cannot be NULL)
    #  *         pubkeylen: pointer to the size of the public key pointed to by pubkey (cannot be NULL)
    #  *                    It will be updated to reflect the new size.
    #  * Returns: 0: pubkey was invalid
    #  *          1: pubkey was valid, and was replaced with its decompressed version
    #  */
    fun secp256k1_ec_pubkey_decompress(ctx : Secp256k1_context_t_ptr,
                                       pubkey : LibC::UChar*,
                                       pubkeylen : Int32*) : Int32

    # /** Export a private key in DER format.
    #  * In: ctx: pointer to a context object, initialized for signing (cannot be NULL)
    #  */
    fun secp256k1_ec_privkey_export(ctx : Secp256k1_context_t_ptr,
                                    seckey : LibC::UChar*,
                                    privkey : LibC::UChar*,
                                    privkeylen : Int32*,
                                    compressed : Int32) : Int32

    # /** Import a private key in DER format. */
    fun secp256k1_ec_privkey_import(ctx : Secp256k1_context_t_ptr,
                                    seckey : LibC::UChar*,
                                    privkey : LibC::UChar*,
                                    privkeylen : Int32) : Int32

    # /** Tweak a private key by adding tweak to it. */
    fun secp256k1_ec_privkey_tweak_add(ctx : Secp256k1_context_t_ptr,
                                       seckey : LibC::UChar*,
                                       tweak : LibC::UChar*) : Int32

    # /** Tweak a public key by adding tweak times the generator to it.
    #  * In: ctx: pointer to a context object, initialized for verification (cannot be NULL)
    #  */
    fun secp256k1_ec_pubkey_tweak_add(ctx : Secp256k1_context_t_ptr, pubkey : LibC::UChar*, pubkeylen : Int32, tweak : LibC::UChar*) : Int32

    # /** Tweak a private key by multiplying it with tweak. */
    fun secp256k1_ec_privkey_tweak_mul(ctx : Secp256k1_context_t_ptr, seckey : LibC::UChar*, tweak : LibC::UChar*) : Int32

    # /** Tweak a public key by multiplying it with tweak.
    #  * In: ctx: pointer to a context object, initialized for verification (cannot be NULL)
    #  */
    fun secp256k1_ec_pubkey_tweak_mul(ctx : Secp256k1_context_t_ptr, pubkey : LibC::UChar*, pubkeylen : Int32, tweak : LibC::UChar*) : Int32

    # /** Updates the context randomization.
    #  *  Returns: 1: randomization successfully updated
    #  *           0: error
    #  *  In:      ctx:       pointer to a context object (cannot be NULL)
    #  *           seed32:    pointer to a 32-byte random seed (NULL resets to initial state)
    #  */
    fun secp256k1_context_randomize(ctx : Secp256k1_context_t_ptr, seed32 : LibC::UChar*) : Int32

    # /** Generate a pedersen commitment.
    #  *  Returns 1: commitment successfully created.
    #  *          0: error
    #  *  In:     ctx:        pointer to a context object, initialized for signing and commitment (cannot be NULL)
    #  *          blind:      pointer to a 32-byte blinding factor (cannot be NULL)
    #  *          value:      unsigned 64-bit integer value to commit to.
    #  *  Out:    commit:     pointer to a 33-byte array for the commitment (cannot be NULL)
    #  *
    #  *  Blinding factors can be generated and verified in the same way as secp256k1 private keys for ECDSA.
    #  */
    fun secp256k1_pedersen_commit(ctx : Secp256k1_context_t_ptr, commit : LibC::UChar*, blind : LibC::UChar*, value : UInt64) : Int32

    # /** Computes the sum of multiple positive and negative blinding factors.
    #  *  Returns 1: sum successfully computed.
    #  *          0: error
    #  *  In:     ctx:        pointer to a context object (cannot be NULL)
    #  *          blinds:     pointer to pointers to 32-byte character arrays for blinding factors. (cannot be NULL)
    #  *          n:          number of factors pointed to by blinds.
    #  *          nneg:       how many of the initial factors should be treated with a positive sign.
    #  *  Out:    blind_out:  pointer to a 32-byte array for the sum (cannot be NULL)
    #  */
    # SECP256K1_WARN_UNUSED_RESULT int secp256k1_pedersen_blind_sum(
    #   const secp256k1_context_t* ctx,
    #   unsigned char *blind_out,
    #   const unsigned char * const *blinds,
    #   int n,
    #   int npositive
    # )SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

    # /** Verify a tally of pedersen commitments
    #  * Returns 1: commitments successfully sum to zero.
    #  *         0: Commitments do not sum to zero or other error.
    #  * In:     ctx:        pointer to a context object, initialized for commitment (cannot be NULL)
    #  *         commits:    pointer to pointers to 33-byte character arrays for the commitments. (cannot be NULL if pcnt is non-zero)
    #  *         pcnt:       number of commitments pointed to by commits.
    #  *         ncommits:   pointer to pointers to 33-byte character arrays for negative commitments. (cannot be NULL if ncnt is non-zero)
    #  *         ncnt:       number of commitments pointed to by ncommits.
    #  *         excess:     signed 64bit amount to add to the total to bring it to zero, can be negative.
    #  *
    #  * This computes sum(commit[0..pcnt)) - sum(ncommit[0..ncnt)) - excess*H == 0.
    #  *
    #  * A pedersen commitment is xG + vH where G and H are generators for the secp256k1 group and x is a blinding factor,
    #  * while v is the committed value. For a collection of commitments to sum to zero both their blinding factors and
    #  * values must sum to zero.
    #  *
    #  */
    # SECP256K1_WARN_UNUSED_RESULT int secp256k1_pedersen_verify_tally(
    #   const secp256k1_context_t* ctx,
    #   const unsigned char * const *commits,
    #   int pcnt,
    #   const unsigned char * const *ncommits,
    #   int ncnt,
    #   int64_t excess
    # )SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4);

    # /** Verify a proof that a committed value is within a range.
    #  * Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs.
    #  *         0: Proof failed or other error.
    #  * In:   ctx: pointer to a context object, initialized for range-proof and commitment (cannot be NULL)
    #  *       commit: the 33-byte commitment being proved. (cannot be NULL)
    #  *       proof: pointer to character array with the proof. (cannot be NULL)
    #  *       plen: length of proof in bytes.
    #  * Out:  min_value: pointer to a unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
    #  *       max_value: pointer to a unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
    #  */
    fun secp256k1_rangeproof_verify(ctx : Secp256k1_context_t_ptr, min_value : UInt64*, max_value : UInt64*, commit : LibC::UChar*, proof : LibC::UChar*, plen : Int32) : Int32

    # /** Verify a range proof proof and rewind the proof to recover information sent by its author.
    #  *  Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs, and the value and blinding were recovered.
    #  *          0: Proof failed, rewind failed, or other error.
    #  *  In:   ctx: pointer to a context object, initialized for range-proof and commitment (cannot be NULL)
    #  *        commit: the 33-byte commitment being proved. (cannot be NULL)
    #  *        proof: pointer to character array with the proof. (cannot be NULL)
    #  *        plen: length of proof in bytes.
    #  *        nonce: 32-byte secret nonce used by the prover (cannot be NULL)
    #  *  In/Out: blind_out: storage for the 32-byte blinding factor used for the commitment
    #  *        value_out: pointer to an unsigned int64 which has the exact value of the commitment.
    #  *        message_out: pointer to a 4096 byte character array to receive message data from the proof author.
    #  *        outlen:  length of message data written to message_out.
    #  *        min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
    #  *        max_value: pointer to an unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
    #  */
    fun secp256k1_rangeproof_rewind(ctx : Secp256k1_context_t_ptr,
                                    blind_out : LibC::UChar*,
                                    value_out : UInt64*,
                                    message_out : LibC::UChar*,
                                    outlen : Int32*,
                                    nonce : LibC::UChar*,
                                    min_value : UInt64*,
                                    max_value : UInt64*,
                                    commit : LibC::UChar*,
                                    proof : LibC::UChar*,
                                    plen : Int32) : Int32

    # /** Author a proof that a committed value is within a range.
    #  *  Returns 1: Proof successfully created.
    #  *          0: Error
    #  *  In:     ctx:    pointer to a context object, initialized for range-proof, signing, and commitment (cannot be NULL)
    #  *          proof:  pointer to array to receive the proof, can be up to 5134 bytes. (cannot be NULL)
    #  *          min_value: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
    #  *          commit: 33-byte array with the commitment being proved.
    #  *          blind:  32-byte blinding factor used by commit.
    #  *          nonce:  32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.)
    #  *          exp:    Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
    #  *                  (-1 is a special case that makes the value public. 0 is the most private.)
    #  *          min_bits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
    #  *          value:  Actual value of the commitment.
    #  *  In/out: plen:   point to an integer with the size of the proof buffer and the size of the constructed proof.
    #  *
    #  *  If min_value or exp is non-zero then the value must be on the range [0, 2^63) to prevent the proof range from spanning past 2^64.
    #  *
    #  *  If exp is -1 the value is revealed by the proof (e.g. it proves that the proof is a blinding of a specific value, without revealing the blinding key.)
    #  *
    #  *  This can randomly fail with probability around one in 2^100. If this happens, buy a lottery ticket and retry with a different nonce or blinding.
    #  *
    #  */
    fun secp256k1_rangeproof_sign(ctx : Secp256k1_context_t_ptr,
                                  proof : LibC::UChar*,
                                  plen : Int32*,
                                  min_value : UInt64,
                                  commit : LibC::UChar*,
                                  blind : LibC::UChar*,
                                  nonce : LibC::UChar*,
                                  exp : Int32,
                                  min_bits : Int32,
                                  value : UInt64) : Int32

    # /** Extract some basic information from a range-proof.
    #  *  Returns 1: Information successfully extracted.
    #  *          0: Decode failed.
    #  *  In:   ctx: pointer to a context object
    #  *        proof: pointer to character array with the proof.
    #  *        plen: length of proof in bytes.
    #  *  Out:  exp: Exponent used in the proof (-1 means the value isn't private).
    #  *        mantissa: Number of bits covered by the proof.
    #  *        min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
    #  *        max_value: pointer to an unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
    #  */
    fun secp256k1_rangeproof_info(ctx : Secp256k1_context_t_ptr,
                                  exp : Int32*,
                                  mantissa : Int32*,
                                  min_value : UInt64*,
                                  max_value : UInt64*,
                                  proof : LibC::UChar*,
                                  plen : Int32) : Int32
  end

  # /**
  #  *  各种数据结构字节数定义
  #  */
  BYTESIZE_PRIVATE_KEY_DATA            = 32
  BYTESIZE_PUBLIC_KEY_POINT            = 65
  BYTESIZE_COMPRESSED_PUBLICK_KEY_DATA = 33
  BYTESIZE_COMPACT_SIGNATURE           = 65
  BYTESIZE_BLIND_FACTOR                = 32
  BYTESIZE_COMMITMENT                  = 33
  BYTESIZE_SHA256                      = 32

  @@__default_context : Context? = nil

  def self.default_context : Context
    @@__default_context ||= Context.new(LibSecp256k1::SECP256K1_CONTEXT_VERIFY | LibSecp256k1::SECP256K1_CONTEXT_SIGN)
    return @@__default_context.not_nil!
  end

  class Context
    def self.default
      return new(LibSecp256k1::SECP256K1_CONTEXT_ALL)
    end

    @flag : Int32
    @ctx : LibSecp256k1::Secp256k1_context_t_ptr

    def to_unsafe
      @ctx
    end

    def initialize(flag = LibSecp256k1::SECP256K1_CONTEXT_ALL, ctx : LibSecp256k1::Secp256k1_context_t_ptr? = nil)
      @ctx = ctx || LibSecp256k1.secp256k1_context_create(flag)
      raise "secp256k1_context_create failed." if @ctx.nil?
      @flag = flag
    end

    def is_valid_public_keydata?(public_keydata : Bytes) : Bool
      return 0 != LibSecp256k1.secp256k1_ec_pubkey_verify(@ctx, public_keydata, public_keydata.size)
    end

    def is_valid_private_keydata?(private_keydata : Bytes) : Bool
      return private_keydata.size == BYTESIZE_PRIVATE_KEY_DATA && 0 != LibSecp256k1.secp256k1_ec_seckey_verify(@ctx, public_keydata)
    end

    def clone
      self.class.new(@flag, LibSecp256k1.secp256k1_context_clone(@ctx))
    end

    def dup
      clone
    end

    def is_canonical?(c : Bytes) : Bool
      return !((c[1] & 0x80) != 0) &&
        !(c[1] == 0 && !((c[2] & 0x80) != 0)) &&
        !((c[33] & 0x80) != 0) &&
        !(c[33] == 0 && !((c[34] & 0x80) != 0))
    end

    def sign_compact(message_digest : Bytes, private_key : PrivateKey, require_canonical = true) : Bytes
      raise "invalid message digest32." if message_digest.size != BYTESIZE_SHA256
      raise "invalid secp256k1 context, missing `SECP256K1_CONTEXT_SIGN` flag." if 0 == (@flag & LibSecp256k1::SECP256K1_CONTEXT_SIGN)

      signature = Bytes.new(BYTESIZE_COMPACT_SIGNATURE)

      extended_nonce_function = ->(nonce32 : LibC::UChar*, msg32 : LibC::UChar*, key32 : LibC::UChar*, attempt : UInt32, data : Void*) {
        extra = data.as(UInt32*)
        extra.value += 1
        return LibSecp256k1.secp256k1_nonce_function_default.call(nonce32, msg32, key32, extra.value, Pointer(Void).new(0))
      }

      # => 循环计算签名，直到找到合适的 canonical 签名。
      recid = 0
      counter = 0
      loop do
        raise "sign compact failed." if 0 == LibSecp256k1.secp256k1_ecdsa_sign_compact(@ctx,
                                          message_digest,
                                          signature[1, BYTESIZE_COMPACT_SIGNATURE - 1],
                                          private_key.bytes,
                                          extended_nonce_function,
                                          pointerof(counter),
                                          pointerof(recid))
        break unless require_canonical && !is_canonical?(signature)
      end

      signature[0] = 27_u8 + 4 + recid

      return signature
    end

    def pedersen_commit(blind_factor : Bytes, value : UInt64) : Bytes
      commit = Bytes.new(BYTESIZE_COMMITMENT)
      raise "pedersen commit failed." if 0 == LibSecp256k1.secp256k1_pedersen_commit(@ctx, commit, blind_factor, value)
      return commit
    end

    # TODO: pedersen_blind_sum(blinds_in, non_neg)
    # TODO: range_proof_sign(min_value, commit, commit_blind, nonce, base10_exp, min_bits, actual_value)

  end

  class PublicKey
    include Secp256k1Zkp::Utility
    extend Secp256k1Zkp::Utility

    def self.from_wif(wif_public_key : String, public_key_prefix : String)
      prefix_size = public_key_prefix.bytesize
      prefix = wif_public_key[0, prefix_size]
      raise "invalid public key prefix." if prefix != public_key_prefix

      raw = base58_decode(wif_public_key[prefix_size..-1])
      checksum_size = 4
      compression_public_key = raw[0, raw.bytesize - checksum_size]
      checksum4 = raw[-checksum_size..-1]
      raise "invalid public key." if checksum4 != rmd160(compression_public_key)[0, checksum_size]

      return new(compression_public_key)
    end

    def initialize(public_keydata : Bytes)
      raise "invalid public key data." unless Secp256k1Zkp.default_context.is_valid_public_keydata?(public_keydata)
      @public_keydata = public_keydata
    end

    def initialize(compact_signature65 : Bytes, digest256 : Bytes, check_canonical = true)
      nV = compact_signature65[0]
      raise "unable to reconstruct public key from signature" if nV < 27 || nV >= 35

      if check_canonical
        raise "signature is not canonical" unless Secp256k1Zkp.default_context.is_canonical?(compact_signature65)
      end

      public_keydata = Bytes.new(BYTESIZE_COMPRESSED_PUBLICK_KEY_DATA)
      pk_len = 0

      raise "recover failed." if 0 == LibSecp256k1.secp256k1_ecdsa_recover_compact(Secp256k1Zkp.default_context,
                                   digest256,
                                   compact_signature65[1, 64],
                                   public_keydata,
                                   pointerof(pk_len),
                                   1, # compressed
                                   (nV - 27) & 3                                 )
      raise "recover failed." if pk_len != public_keydata.size

      @public_keydata = public_keydata
    end

    def bytes
      @public_keydata
    end

    def to_wif(public_key_prefix : String)
      checksum = rmd160(self.bytes)
      addr = self.bytes + checksum[0, 4]
      return public_key_prefix + base58_encode(addr)
    end

    def to_address(addr_prefix : String) : String
      bin_addr = to_address
      checksum = rmd160(bin_addr)
      return addr_prefix + base58_encode(bin_addr + checksum[0, 4])
    end

    # => (public) 生成bts地址（序列化时公钥排序会用到。）
    def to_address : Bytes
      return rmd160(sha512(self.bytes))
    end

    def shared_secret(private_key : PrivateKey)
      share_public_key = self * private_key.bytes
      return sha512(share_public_key.bytes[1..-1])
    end

    def tweak_add(tweak : Bytes)
      raise "invalid private key data." if tweak.size != BYTESIZE_PRIVATE_KEY_DATA
      new_public_key = self.bytes.clone
      raise "tweak error." if 0 == LibSecp256k1.secp256k1_ec_pubkey_tweak_add(Secp256k1Zkp.default_context, new_public_key, new_public_key.size, tweak)
      return self.class.new(new_public_key)
    end

    def +(tweak : Bytes)
      tweak_add(tweak)
    end

    def tweak_mul(tweak : Bytes)
      raise "invalid private key data." if tweak.size != BYTESIZE_PRIVATE_KEY_DATA
      new_public_key = self.bytes.clone
      raise "tweak error." if 0 == LibSecp256k1.secp256k1_ec_pubkey_tweak_mul(Secp256k1Zkp.default_context, new_public_key, new_public_key.size, tweak)
      return self.class.new(new_public_key)
    end

    def *(tweak : Bytes)
      tweak_mul(tweak)
    end
  end

  class PrivateKey
    include Secp256k1Zkp::Utility
    extend Secp256k1Zkp::Utility

    def bytes
      @private_keydata
    end

    def initialize(private_keydata : Bytes)
      @private_keydata = private_keydata
    end

    # include Secp256k1Zkp::Utility

    # SECP256K1_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # def self.nonce
    #   # => 私钥有效范围。[1, SECP256K1_CURVE_ORDER)。 REMARK：大部分 lib 范围是 [1, SECP256K1_CURVE_ORDER] 的闭区间，该C库范围为开区间。
    #   # SecureRandom.random_number(SECP256K1_CURVE_ORDER - 1) + 1
    # end

    def self.random
      # TODO: 私钥有效范围。[1, SECP256K1_CURVE_ORDER) nonce
      private_keydata = Bytes.new(Secp256k1Zkp::BYTESIZE_PRIVATE_KEY_DATA)
      Random::Secure.random_bytes(private_keydata)
      return new(private_keydata)
    end

    # => role - owner / active
    def self.from_account_and_password(account, password, role = "active")
      return from_seed("#{account}#{role}#{password}")
    end

    def self.from_seed(seed)
      return new(sha256(seed))
    end

    def self.from_wif(wif_private_key_string : String)
      raw = base58_decode(wif_private_key_string)
      version = raw[0]
      raise "invalid private key." if version != 0x80
      # => raw = [1B]0x80 + [32B]privatekey + [4B]checksum
      checksum_size = 4
      checksum4 = raw[-checksum_size..-1]
      private_key_with_prefix = raw[0...-checksum_size]
      digest = sha256(sha256(private_key_with_prefix))
      raise "invalid private key." if checksum4 != digest[0, checksum_size]
      return new(raw[1, 32])
    end

    def tweak_add(tweak : Bytes)
      raise "invalid private key data." if tweak.size != BYTESIZE_PRIVATE_KEY_DATA
      new_private_key = self.bytes.clone
      raise "tweak error." if 0 == LibSecp256k1.secp256k1_ec_privkey_tweak_add(Secp256k1Zkp.default_context, new_private_key, tweak)
      return self.class.new(new_private_key)
    end

    def +(tweak : Bytes)
      tweak_add(tweak)
    end

    def tweak_mul(tweak : Bytes)
      raise "invalid private key data." if tweak.size != BYTESIZE_PRIVATE_KEY_DATA
      new_private_key = self.bytes.clone
      raise "tweak error." if 0 == LibSecp256k1.secp256k1_ec_privkey_tweak_mul(Secp256k1Zkp.default_context, new_private_key, tweak)
      return self.class.new(new_private_key)
    end

    def *(tweak : Bytes)
      tweak_mul(tweak)
    end

    def to_public_key
      new_public_key = Bytes.new(BYTESIZE_COMPRESSED_PUBLICK_KEY_DATA)
      pubkey_len = new_public_key.size
      raise "generate public key error." if 0 == LibSecp256k1.secp256k1_ec_pubkey_create(Secp256k1Zkp.default_context, new_public_key, pointerof(pubkey_len), self.bytes, 1)
      return PublicKey.new(new_public_key)
    end

    def to_wif
      private_key_with_prefix = Bytes[0x80] + self.bytes
      checksum = sha256(sha256(private_key_with_prefix))[0, 4]
      return base58_encode(private_key_with_prefix + checksum)
    end

    def shared_secret(public_key : PublicKey)
      share_public_key = public_key * self.bytes
      return sha512(share_public_key.bytes[1..-1])
    end
  end
end
