-module(hotp_SUITE).
%% Callbacks
-export([all/0, groups/0]).

%% Test cases
-export([t_rfc/1, t_new/1]).

-define(GROUP, hotp).

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() -> [{group, ?GROUP}].

groups() ->
  Tests = [t_rfc, t_new],
  Properties = [parallel],
  [{?GROUP, Properties, Tests}].


%%%===================================================================
%%%  Test cases
%%%===================================================================

t_rfc(_Cfg) -> hotp:tests_rfc4226().

t_new(_Cfg) ->
  lists:foreach(
    fun (Length) ->
        lists:foreach(
          fun (HashAlgo) ->
              Secret1 = hotp_secret:new(HashAlgo),
              Secret2 = hotp_secret:new(HashAlgo),
              Count1  = 1,
              Count2  = 2,
              Opts    = [{hash_algo, HashAlgo}
                        , {length,    Length}
                        ],
              HOTP    = hotp:cons(Secret1, Count1, Opts),
              ct:log("Length: ~b, HashAlgo: ~p, HOTP: ~b~n",
                     [Length, HashAlgo, HOTP]),
              HOTP =   hotp:cons(Secret1, Count1, Opts),
              true = HOTP =/= hotp:cons(Secret1, Count2, Opts),
              true = HOTP =/= hotp:cons(Secret2, Count1, Opts),
              true = HOTP =/= hotp:cons(Secret2, Count2, Opts)
          end,
          hotp_hmac:hash_algos_supported()
         )
    end,
    [6, 8]).
