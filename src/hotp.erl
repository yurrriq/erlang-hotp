-module(hotp).

-export_type([hotp_opts/0, hotp_opt/0]).

-export([cons/2, cons/3]).

-ifdef(TEST).
-export([tests_rfc4226/0]).
-endif.

-type hotp_opt() :: {hash_algo, hotp_hmac:hash_algo()}
                  | {length, pos_integer()}.

-type hotp_opts() :: [hotp_opt()].

-spec cons(binary(), pos_integer()) -> integer().
cons(<<Secret/binary>>, Count) -> cons(Secret, Count, []).

-spec cons(binary(), pos_integer(), hotp_opts()) -> pos_integer().
cons(<<Secret/binary>>, Count, Opts) ->
  HashAlgo = proplists:get_value(hash_algo, Opts, sha),
  Length   = proplists:get_value(length, Opts, 6),
  CountBin = count_to_bin(Count),
  Digest   = hotp_hmac:cons(HashAlgo, Secret, CountBin),
  Number   = digest_truncate(Digest),
  int_truncate(Number, Length).

-spec count_to_bin(pos_integer()) -> binary().
count_to_bin(Count) -> <<Count:64/integer>>.

-spec digest_truncate(<<_:32,_:_*8>>) -> non_neg_integer().
digest_truncate(Digest) ->
  Offset1 = byte_size(Digest) - 1,
  <<_:Offset1/bytes, _:4/bits,               Offset2:4/integer >> = Digest,
  <<_:Offset2/bytes, _:1/bits, P:31/integer,         _/binary  >> = Digest,
  P.

-spec int_truncate(integer(), pos_integer()) -> pos_integer().
int_truncate(Number, Length) -> Number rem trunc(math:pow(10, Length)).


%%%======================================================================
%%% Tests from RFC 4226 (https://tools.ietf.org/html/rfc4226#appendix-D)
%%%======================================================================

-ifdef(TEST).
-record(test_case,
        {secret           :: binary(),
         count            :: pos_integer(),
         digest_full_hex  :: binary(),
         digest_trunc_hex :: binary(),
         digest_trunc_dec :: pos_integer(),
         hotp             :: pos_integer()}).

tests_rfc4226() ->
  lists:foreach(fun test_case_execute/1, test_cases_from_rfc4226()).

test_case_execute(#test_case{ secret           = Secret
                            , count            = Count
                            , digest_full_hex  = DigestFullHex
                            , digest_trunc_hex = _DigestTruncHex
                            , digest_trunc_dec = DigestTruncDec
                            , hotp             = HOTP
                            }) ->
  CountBin = count_to_bin(Count),
  Digest   = hotp_hmac:cons(sha, Secret, CountBin),
  <<DigestFullDec:160/integer>> = Digest,
  DigestFullHex  = list_to_binary(io_lib:format("~40.16.0b", [DigestFullDec])),
  DigestTruncDec = digest_truncate(Digest),
  HOTP = int_truncate(DigestTruncDec, 6),
  HOTP = cons(Secret, Count).

test_cases_from_rfc4226() ->
  Secret = <<"12345678901234567890">>,
  [ #test_case{ secret           = Secret
              , count            = 0
              , digest_full_hex  = <<"cc93cf18508d94934c64b65d8ba7667fb7cde4b0">>
              , digest_trunc_hex = <<"4c93cf18">>
              , digest_trunc_dec = 1284755224
              , hotp             = 755224
              }
  , #test_case{ secret           = Secret
              , count            = 1
              , digest_full_hex  = <<"75a48a19d4cbe100644e8ac1397eea747a2d33ab">>
              , digest_trunc_hex = <<"41397eea">>
              , digest_trunc_dec = 1094287082
              , hotp = 287082
              }
  , #test_case{ secret           = Secret
              , count            = 2
              , digest_full_hex  = <<"0bacb7fa082fef30782211938bc1c5e70416ff44">>
              , digest_trunc_hex = <<"82fef30">>
              , digest_trunc_dec = 137359152
              , hotp             = 359152
              }
  , #test_case{ secret           = Secret
              , count            = 3
              , digest_full_hex  = <<"66c28227d03a2d5529262ff016a1e6ef76557ece">>
              , digest_trunc_hex = <<"66ef7655">>
              , digest_trunc_dec = 1726969429
              , hotp             = 969429
              }
  , #test_case{ secret           = Secret
              , count            = 4
              , digest_full_hex  = <<"a904c900a64b35909874b33e61c5938a8e15ed1c">>
              , digest_trunc_hex = <<"61c5938a">>
              , digest_trunc_dec = 1640338314
              , hotp             = 338314
              }
  , #test_case{ secret           = Secret
              , count            = 5
              , digest_full_hex  = <<"a37e783d7b7233c083d4f62926c7a25f238d0316">>
              , digest_trunc_hex = <<"33c083d4">>
              , digest_trunc_dec = 868254676
              , hotp             = 254676
              }
  , #test_case{ secret           = Secret
              , count            = 6
              , digest_full_hex  = <<"bc9cd28561042c83f219324d3c607256c03272ae">>
              , digest_trunc_hex = <<"7256c032">>
              , digest_trunc_dec = 1918287922
              , hotp             = 287922
              }
  , #test_case{ secret           = Secret
              , count            = 7
              , digest_full_hex  = <<"a4fb960c0bc06e1eabb804e5b397cdc4b45596fa">>
              , digest_trunc_hex = <<"4e5b397">>
              , digest_trunc_dec = 82162583
              , hotp             = 162583
              }
  , #test_case{ secret           = Secret
              , count            = 8
              , digest_full_hex  = <<"1b3c89f65e6c9e883012052823443f048b4332db">>
              , digest_trunc_hex = <<"2823443f">>
              , digest_trunc_dec = 673399871
              , hotp             = 399871
              }
  , #test_case{ secret           = Secret
              , count            = 9
              , digest_full_hex  = <<"1637409809a679dc698207310c8c7fc07290d9e5">>
              , digest_trunc_hex = <<"2679dc69">>
              , digest_trunc_dec = 645520489
              , hotp             = 520489
              }
  ].
-endif.
