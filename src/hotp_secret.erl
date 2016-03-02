-module(hotp_secret).

-export([new/0, new/1]).

-spec new() -> binary().
new() -> new(sha).

-spec new(hotp_hmac:hash_algo()) -> binary().
new(HashAlgo) ->
  NumOfBytes = num_of_bytes_needed_for_hash_algo(HashAlgo),
  crypto:strong_rand_bytes(NumOfBytes).

num_of_bytes_needed_for_hash_algo(sha)      -> 20;
num_of_bytes_needed_for_hash_algo(sha256)   -> 32;
num_of_bytes_needed_for_hash_algo(sha512)   -> 64;
num_of_bytes_needed_for_hash_algo(HashAlgo) -> error({bad_hash_algo, HashAlgo}).
