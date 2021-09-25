# TODO: Write documentation for `Secp256k1Zkp`
module Secp256k1Zkp
  VERSION = "0.9.0"

  # 静态链接直接链接指定目录，动态链接忽略。
  @[Link(ldflags: "-L#{__DIR__}/../secp256k1-zkp/.libs -lsecp256k1 -lgmp")]
  lib LibSecp256k1
    # Flags to pass to secp256k1_context_create.
    SECP256K1_CONTEXT_VERIFY     = (1 << 0)
    SECP256K1_CONTEXT_SIGN       = (1 << 1)
    SECP256K1_CONTEXT_COMMIT     = (1 << 7)
    SECP256K1_CONTEXT_RANGEPROOF = (1 << 8)

    SECP256K1_CONTEXT_ALL = SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_COMMIT | SECP256K1_CONTEXT_RANGEPROOF

    type Secp256k1_context_t_ptr = Void*

    # if (!_g_secp256k1_context_ptr)
    # {
    #   _g_secp256k1_context_ptr = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    # }

    # $g_secp256k1_context_ptr : Secp256k1_context_t_ptr #
    # LibSecp256k1.g_secp256k1_context_ptr = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    # raise "" if $g_secp256k1_context_ptr.nil?

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
    type Secp256k1_nonce_function_t = (LibC::UChar*, LibC::UChar*, LibC::UChar*, UInt32, Void*) -> Int32

    # /** An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
    #  * If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
    #  * extra entropy.
    #  */
    # extern const secp256k1_nonce_function_t secp256k1_nonce_function_rfc6979;

    # /** A default safe nonce generation function (currently equal to secp256k1_nonce_function_rfc6979). */
    # extern const secp256k1_nonce_function_t secp256k1_nonce_function_default;

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

  # //  Secp256k1Zkp::Context
  # rb_cSecp256k1Context = rb_define_class_under(rb_mSecp256k1, "Context", rb_cObject);

  # rb_undef_alloc_func(rb_cSecp256k1Context);
  # rb_define_alloc_func(rb_cSecp256k1Context, dm_context_alloc);
  # rb_define_method(rb_cSecp256k1Context, "initialize", dm_context_initialize, 1);
  # rb_define_method(rb_cSecp256k1Context, "is_valid_public_keydata?", dm_context_verify_public_keydata, 1);
  # rb_define_method(rb_cSecp256k1Context, "is_valid_private_keydata?", dm_context_verify_private_keydata, 1);
  # rb_define_method(rb_cSecp256k1Context, "clone", dm_context_clone, 0);
  # rb_define_method(rb_cSecp256k1Context, "dup", dm_context_clone, 0);
  # rb_define_method(rb_cSecp256k1Context, "sign_compact", dm_context_sign_compact, -1);
  # rb_define_method(rb_cSecp256k1Context, "pedersen_commit", dm_context_pedersen_commit, 2);
  # rb_define_method(rb_cSecp256k1Context, "pedersen_blind_sum", dm_context_pedersen_blind_sum, 2);
  # rb_define_method(rb_cSecp256k1Context, "range_proof_sign", dm_context_range_proof_sign, 7);

  # //  Secp256k1Zkp::PublicKey
  # rb_cSecp256k1PublicKey = rb_define_class_under(rb_mSecp256k1, "PublicKey", rb_cObject);

  # rb_undef_alloc_func(rb_cSecp256k1PublicKey);
  # rb_define_alloc_func(rb_cSecp256k1PublicKey, dm_public_key_alloc);
  # rb_define_method(rb_cSecp256k1PublicKey, "initialize", dm_public_key_initialize, 1);
  # rb_define_method(rb_cSecp256k1PublicKey, "bytes", dm_public_key_bytes, 0);
  # rb_define_method(rb_cSecp256k1PublicKey, "tweak_add", dm_public_key_tweak_add, 1);
  # rb_define_method(rb_cSecp256k1PublicKey, "tweak_mul", dm_public_key_tweak_mul, 1);
  # rb_define_alias(rb_cSecp256k1PublicKey, "+", "tweak_add");
  # rb_define_alias(rb_cSecp256k1PublicKey, "*", "tweak_mul");

  # //  Secp256k1Zkp::PrivateKey
  # rb_cSecp256k1PrivateKey = rb_define_class_under(rb_mSecp256k1, "PrivateKey", rb_cObject);

  # rb_undef_alloc_func(rb_cSecp256k1PrivateKey);
  # rb_define_alloc_func(rb_cSecp256k1PrivateKey, dm_private_key_alloc);
  # rb_define_method(rb_cSecp256k1PrivateKey, "initialize", dm_private_key_initialize, 1);
  # rb_define_method(rb_cSecp256k1PrivateKey, "bytes", dm_private_key_bytes, 0);
  # rb_define_method(rb_cSecp256k1PrivateKey, "tweak_add", dm_private_key_tweak_add, 1);
  # rb_define_method(rb_cSecp256k1PrivateKey, "tweak_mul", dm_private_key_tweak_mul, 1);
  # rb_define_alias(rb_cSecp256k1PrivateKey, "+", "tweak_add");
  # rb_define_alias(rb_cSecp256k1PrivateKey, "*", "tweak_mul");
  # rb_define_method(rb_cSecp256k1PrivateKey, "to_public_key", dm_private_key_to_public_key, 0);

  # /**
  #  *  各种数据结构字节数定义
  #  */
  # #define kByteSizePrivateKeyData 32
  # #define kByteSizePublicKeyPoint 65
  # #define kByteSizeCompressedPublicKeyData 33
  # #define kByteSizeCompactSignature 65
  # #define kByteSizeBlindFactor 32
  # #define kByteSizeCommitment 33
  # #define kByteSizeSha256 32

  # typedef struct
  # {
  #   unsigned char data[kByteSizePrivateKeyData];
  # } rb_struct_private_key;

  # //  the full non-compressed version of the ECC point
  # typedef struct
  # {
  #   unsigned char data[kByteSizePublicKeyPoint];
  # } rb_struct_pubkey_point;

  # typedef struct
  # {
  #   unsigned char data[kByteSizeCompressedPublicKeyData];
  # } rb_struct_pubkey_compressed;

  # typedef struct
  # {
  #   unsigned char data[kByteSizeCompactSignature];
  # } rb_struct_compact_signature;

  # typedef struct
  # {
  #   unsigned char data[kByteSizeBlindFactor];
  # } rb_struct_blind_factor_type;

  # typedef struct
  # {
  #   unsigned char data[kByteSizeCommitment];
  # } rb_struct_commitment_type;

  @@g_secp256k1_context_ptr : LibSecp256k1::Secp256k1_context_t_ptr? = nil

  def self.g_secp256k1_context_ptr : LibSecp256k1::Secp256k1_context_t_ptr
    if @@g_secp256k1_context_ptr.nil?
      @@g_secp256k1_context_ptr = LibSecp256k1.secp256k1_context_create(LibSecp256k1::SECP256K1_CONTEXT_VERIFY | LibSecp256k1::SECP256K1_CONTEXT_SIGN)
    end
    raise "secp256k1_context_create failed." if @@g_secp256k1_context_ptr.nil?
    return @@g_secp256k1_context_ptr.not_nil!
  end

  class Context
    def self.default
      return new(LibSecp256k1::SECP256K1_CONTEXT_ALL)
    end

    def initialize(flag = LibSecp256k1::SECP256K1_CONTEXT_ALL)
      @ctx = LibSecp256k1.secp256k1_context_create(flag)
      raise "secp256k1_context_create failed." if @ctx.nil?
    end

    def is_valid_public_keydata?(public_keydata : String) : Bool
      bytes = public_keydata.to_slice
      return nif 0 != secp256k1_ec_pubkey_verify(@ctx, bytes.to_unsafe, bytes.size)
    end

    def is_valid_private_keydata?(private_keydata : String) : Bool
      # => TODO:
      # secp256k1_ec_seckey_verify
    end

    def sign_compact(message_digest, private_key, require_canonical = true)
      # => TODO:
      secp256k1_ecdsa_sign_compact(@ctx, nil, nil, nil, nil, nil, nil)
      # secp256k1_ecdsa_sign_compact
      # fun secp256k1_ecdsa_sign_compact(ctx : Secp256k1_context_t_ptr,
      #                                msg32 : LibC::UChar*,
      #                                sig64 : LibC::UChar*,
      #                                seckey : LibC::UChar*,
      #                                noncefp : Secp256k1_nonce_function_t,
      #                                ndata : Void*,
      #                                recid : Int32*) : Int32
    end
  end

  class PublicKey
    # include Secp256k1Zkp::Utility

    def self.from_wif(wif_public_key : String, public_key_prefix = "BTS")
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
      raise "invalid public key data." if 0 == LibSecp256k1.secp256k1_ec_pubkey_verify(Secp256k1Zkp.g_secp256k1_context_ptr, public_keydata, public_keydata.size)
      @public_keydata = public_keydata
    end

    private def bytes
      @public_keydata
    end

    def to_wif(public_key_prefix = "BTS")
      checksum = rmd160(self.bytes)

      # => addr = self.bytes + checksum[0, 4]
      io = IO::Memory.new
      io.write(self.bytes)
      io.write(checksum[0, 4])
      addr = io.to_slice

      return public_key_prefix + base58_encode(addr)
    end

    # # => (public) 生成bts地址（序列化时公钥排序会用到。）
    # def to_blockchain_address
    #   return rmd160(sha512(self.bytes))
    # end

    # def shared_secret(private_key)
    #   share_public_key = self * private_key.bytes
    #   return sha512(share_public_key.bytes[1..-1])
    # end
  end

  class PrivateKey
    def initialize(private_keydata)
    end
  end
end
