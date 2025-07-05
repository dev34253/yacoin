DIST_SUBDIRS = secp256k1 univalue
AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS)

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)
BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBYACOIN_COMMON=libyacoin_common.a
LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

EXTRA_LIBRARIES = \
  libyacoin_common.a

LIBBITCOIN_CONSENSUS=
bin_PROGRAMS =
TESTS =
 
if BUILD_BITCOIND
  bin_PROGRAMS += yacoind
endif

BUILT_SOURCES = obj/build.h

obj/build.h:
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)

libyacoin_common_a-clientversion.cpp: obj/build.h

SCRYPTDEFS=-DBOOST_SPIRIT_THREADSAFE -DUSE_ASM 
SCRYPTHARDENING=-fno-stack-protector -fstack-protector-all -Wstack-protector -D_FORTIFY_SOURCE=2 -fPIC
xCXXFLAGS=-O2 -msse2 -pthread -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter $(SCRYPTDEFS) $(SCRYPTHARDENING) -std=c++0x

# yacoind-scrypt-x86.o: scrypt-x86.S
# 	$(CXX) -c $(xCXXFLAGS) -MMD -o $@ $<

# yacoind-scrypt-x86_64.o: scrypt-x86_64.S
# 	$(CXX) -c $(xCXXFLAGS) -MMD -o $@ $<

SCRYPTDEFS+=-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA -DSCRYPT_CHOOSE_COMPILETIME
DEFS+=-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA -DSCRYPT_CHOOSE_COMPILETIME

xCXXFLAGS_SCRYPT_JANE=-O3 -msse2 -pthread -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter -DUSE_ASM $(DEBUGFLAGS) $(SCRYPTDEFS) $(SCRYPTHARDENING) 
yacoind-scrypt-jane.o: scrypt-jane/scrypt-jane.c
	gcc -c $(xCXXFLAGS_SCRYPT_JANE) -MMD -o $@ $<

libyacoin_common_a_SOURCES= \
    tokens/tokentypes.cpp \
    tokens/tokendb.cpp \
    tokens/tokens.cpp \
    chain.cpp \
    chainparams.cpp \
    chainparamsbase.cpp \
    crypto/aes.cpp \
    crypto/siphash.cpp \
    crypto/chacha20.cpp \
    crypto/sha1.cpp \
    crypto/sha256.cpp \
    crypto/sha512.cpp \
    crypto/ripemd160.cpp \
    crypto/hmac_sha256.cpp \
    crypto/hmac_sha512.cpp \
    compat/strnlen.cpp \
    coins.cpp \
    compressor.cpp \
    consensus/consensus.cpp \
    consensus/tx_verify.cpp \
    primitives/transaction.cpp \
    primitives/block.cpp \
    merkleblock.cpp \
    blockencodings.cpp \
    policy/feerate.cpp \
    policy/fees.cpp \
    policy/policy.cpp \
    pow.cpp \
    support/cleanse.cpp \
    support/lockedpool.cpp \
    dbwrapper.cpp \
    txdb.cpp \
    hash.cpp \
    base58.cpp \
    clientversion.cpp \
    checkpoints.cpp \
    netbase.cpp \
    addrman.cpp \
    addrdb.cpp \
    bloom.cpp \
    threadinterrupt.cpp \
    compressor.cpp \
    key.cpp \
    fs.cpp \
    validation.cpp \
    validationinterface.cpp \
    scheduler.cpp \
    torcontrol.cpp \
    random.cpp \
    keystore.cpp \
    kernelrecord.cpp \
    LibBoolEE.cpp \
    stun.cpp \
    miner.cpp \
    main.cpp \
    net.cpp \
    arith_uint256.cpp \
    net_processing.cpp \
    protocol.cpp \
    pubkey.cpp \
    rpc/bitcoinrpc.cpp \
    price.cpp \
    random_nonce.cpp \
    rpc/tokens.cpp \
    rpc/net.cpp \
    rpc/mining.cpp \
    rpc/misc.cpp \
    rpc/blockchain.cpp \
    rpc/rawtransaction.cpp \
    script/interpreter.cpp \
    script/ismine.cpp \
    script/script.cpp \
    script/script_error.cpp \
    script/sigcache.cpp \
    script/sign.cpp \
    script/standard.cpp \
    sync.cpp \
    util.cpp \
    utilstrencodings.cpp \
    utilmoneystr.cpp \
    utiltime.cpp \
    ui_interface.cpp \
    netaddress.cpp \
    timedata.cpp \
    warnings.cpp \
    txmempool.cpp \
    wallet/crypter.cpp \
    wallet/db.cpp \
    wallet/rpcdump.cpp \
    wallet/rpcwallet.cpp \
    wallet/wallet.cpp \
    wallet/walletdb.cpp \
    noui.cpp \
    kernel.cpp \
    pbkdf2.cpp \
    scrypt.cpp \
    scrypt-x86.S \
    scrypt-x86_64.S \
    scrypt-generic.cpp \
    scrypt-jane/scrypt-jane.c

libyacoin_common_a_CPPFLAGS = $(BITCOIN_INCLUDES)
libyacoin_common_a_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -ldl -lpthread -lrt -L$(srcdir)/src/secp256k1/.libs

yacoind_SOURCES = init.cpp

yacoind_LDADD = $(LIBYACOIN_COMMON)
yacoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(LIBLEVELDB) $(LIBLEVELDB_SSE42) $(LIBMEMENV) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(LIBSECP256K1) $(LIBUNIVALUE)
yacoind_CPPFLAGS = $(BITCOIN_INCLUDES)
yacoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -ldl -lpthread -lrt

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb $(CTAES_DIST)

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

# .mm.o:
# 	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
# 	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(CXXFLAGS)  -c -o $@ $<

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_TESTS
bin_PROGRAMS+=yacoin_test
yacoin_test_SOURCES= \
  test/accounting_tests.cpp \
  test/allocator_tests.cpp \
  test/base32_tests.cpp \
  test/base64_tests.cpp \
  test/bignum_tests.cpp \
  test/getarg_tests.cpp \
  test/mruset_tests.cpp \
  test/multisig_tests.cpp \
  test/rpc_tests.cpp \
  test/script_P2SH_tests.cpp \
  test/sigopcount_tests.cpp \
  test/script_tests.cpp \
  test/test_bitcoin.cpp \
  test/transaction_tests.cpp \
  test/util_tests.cpp \
  test/wallet_tests.cpp \
  test/uint160_tests.cpp \
  test/uint256_tests.cpp \
  init.cpp

# FAILING tests
#  test/miner_tests.cpp \
#  test/key_tests.cpp \
#  test/base58_tests.cpp \
#  test/netbase_tests.cpp \
#  test/Checkpoints_tests.cpp 

yacoin_test_LDADD = $(LIBYACOIN_COMMON)
yacoin_test_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(LIBLEVELDB) $(LIBMEMENV)  $(BOOST_UNIT_TEST_FRAMEWORK_LIB)
yacoin_test_CPPFLAGS = $(BITCOIN_INCLUDES) -DTESTS_ENABLED
yacoin_test_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -ldl -lpthread -lrt
endif
