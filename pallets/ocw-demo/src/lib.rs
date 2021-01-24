//! A demonstration of an offchain worker that sends onchain callbacks

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

use core::{convert::TryInto, fmt};
use frame_support::{
    debug, decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult,
};
use parity_scale_codec::{Decode, Encode};

use frame_system::{
    self as system, ensure_none, ensure_signed,
    offchain::{
        AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
        SignedPayload, Signer, SigningTypes, SubmitTransaction,
    },
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
    offchain as rt_offchain,
    offchain::{
        storage::StorageValueRef,
        storage_lock::{BlockAndTime, StorageLock},
    },
    transaction_validity::{
        InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
    },
    RuntimeDebug,
};
use sp_std::{collections::vec_deque::VecDeque, prelude::*, str};

use serde::{Deserialize, Deserializer};

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When an offchain worker is signing transactions it's going to request keys from type
/// `KeyTypeId` via the keystore to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
pub const NUM_VEC_LEN: usize = 10;
/// The type to sign and send transactions.
pub const UNSIGNED_TXS_PRIORITY: u64 = 100;

// We are fetching information from the github public API about organization`substrate-developer-hub`.
pub const HTTP_REMOTE_REQUEST: &str = "https://api.github.com/orgs/substrate-developer-hub";
pub const HTTP_REMOTE_REQUEST_DOTPRICE: &str = "https://api.coincap.io/v2/assets/polkadot";
pub const HTTP_HEADER_USER_AGENT: &str = "jimmychu0807";

pub const FETCH_TIMEOUT_PERIOD: u64 = 3000; // in milli-seconds
pub const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000; // in milli-seconds
pub const LOCK_BLOCK_EXPIRATION: u32 = 3; // in block number

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// them with the pallet-specific identifier.
pub mod crypto {
    use crate::KEY_TYPE;
    use sp_core::sr25519::Signature as Sr25519Signature;
    use sp_runtime::app_crypto::{app_crypto, sr25519};
    use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};

    app_crypto!(sr25519, KEY_TYPE);

    pub struct TestAuthId;
    // implemented for ocw-runtime
    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }

    // implemented for mock runtime in test
    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
        for TestAuthId
    {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Payload<Public> {
    dotprice: u32,
    public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

// ref: https://serde.rs/container-attrs.html#crate
#[derive(Deserialize, Encode, Decode, Default)]
struct GithubInfo {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    login: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    blog: Vec<u8>,
    public_repos: u32,
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    Ok(s.as_bytes().to_vec())
}

impl fmt::Debug for GithubInfo {
    // `fmt` converts the vector of bytes inside the struct back to string for
    //   more friendly display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ login: {}, blog: {}, public_repos: {} }}",
            str::from_utf8(&self.login).map_err(|_| fmt::Error)?,
            str::from_utf8(&self.blog).map_err(|_| fmt::Error)?,
            &self.public_repos
        )
    }
}

#[derive(Deserialize, Encode, Decode, Default)]
struct DotPriceData {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    #[serde(rename = "priceUsd")]
    price_usd: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    symbol: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    name: Vec<u8>,
}

#[derive(Deserialize, Encode, Decode, Default)]
struct DotPrice {
    data: DotPriceData,
    timestamp: u64,
}

impl fmt::Debug for DotPrice {
    // `fmt` converts the vector of bytes inside the struct back to string for
    //   more friendly display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ symbol: {}, price_usd: {}, timestamp: {} }}",
            str::from_utf8(&self.data.symbol).map_err(|_| fmt::Error)?,
            str::from_utf8(&self.data.price_usd).map_err(|_| fmt::Error)?,
            &self.timestamp
        )
    }
}

/// This is the pallet's configuration trait
pub trait Trait: system::Trait + CreateSignedTransaction<Call<Self>> {
    /// The identifier type for an offchain worker.
    type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
    /// The overarching dispatch call type.
    type Call: From<Call<Self>>;
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as Example {
        /// A vector of recently submitted numbers. Bounded by NUM_VEC_LEN
        DotPrices get(fn dot_prices): VecDeque<u32>;
    }
}

decl_event!(
    /// Events generated by the module.
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        /// Event generated when a new number is accepted to contribute to the average.
        NewDotPrice(Option<AccountId>, u32),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        // Error returned when not sure which ocw function to executed
        UnknownOffchainMux,

        // Error returned when making signed transactions in off-chain worker
        NoLocalAcctForSigning,
        OffchainSignedTxError,

        // Error returned when making unsigned transactions in off-chain worker
        OffchainUnsignedTxError,

        // Error returned when making unsigned transactions with signed payloads in off-chain worker
        OffchainUnsignedTxSignedPayloadError,

        // Error returned when fetching github info
        HttpFetchingError,

        // Error returned when sending request
        HttpSendingError,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        #[weight = 10000]
        pub fn submit_dotprice_signed(origin, dotprice: u32) -> DispatchResult {
            let who = ensure_signed(origin)?;
            debug::info!("submit_dotprice_signed: ({}, {:?})", dotprice, who);
            Self::append_or_replace_dotprice(dotprice);

            Self::deposit_event(RawEvent::NewDotPrice(Some(who), dotprice));
            Ok(())
        }

        #[weight = 10000]
        pub fn submit_dotprice_unsigned(origin, dotprice: u32) -> DispatchResult {
            let _ = ensure_none(origin)?;
            debug::info!("submit_dotprice_unsigned: {}", dotprice);
            Self::append_or_replace_dotprice(dotprice);

            Self::deposit_event(RawEvent::NewDotPrice(None, dotprice));
            Ok(())
        }

        #[weight = 10000]
        pub fn submit_dotprice_unsigned_with_signed_payload(origin, payload: Payload<T::Public>,
            _signature: T::Signature) -> DispatchResult
        {
            let _ = ensure_none(origin)?;
            // we don't need to verify the signature here because it has been verified in
            //   `validate_unsigned` function when sending out the unsigned tx.
            let Payload { dotprice, public } = payload;
            debug::info!("submit_dotprice_unsigned_with_signed_payload: ({}, {:?})", dotprice, public);
            Self::append_or_replace_dotprice(dotprice);

            Self::deposit_event(RawEvent::NewDotPrice(None, dotprice));
            Ok(())
        }

        fn offchain_worker(block_number: T::BlockNumber) {
            debug::info!("Entering off-chain worker");

            // Here we are showcasing various techniques used when running off-chain workers (ocw)
            // 1. Sending signed transaction from ocw
            // 2. Sending unsigned transaction from ocw
            // 3. Sending unsigned transactions with signed payloads from ocw
            // 4. Fetching JSON via http requests in ocw
            const TX_TYPES: u32 = 4;
            let modu = block_number.try_into().map_or(TX_TYPES, |bn: u32| bn % TX_TYPES);
            let _ = Self::update_dot_price(modu);
        }
    }
}

impl<T: Trait> Module<T> {
    /// Check if we have fetched dot price before. If yes, we can use the cached version
    ///   stored in off-chain worker storage `storage`. If not, we fetch the remote info and
    ///   write the info into the storage for future retrieval.
    fn update_dot_price(block_number: u32) -> Result<(), Error<T>> {
        // Create a reference to Local Storage value.
        // Since the local storage is common for all offchain workers, it's a good practice
        // to prepend our entry with the pallet name.
        let s_info = StorageValueRef::persistent(b"offchain-demo::dot-price");

        let mut dot_info = s_info
            .get::<VecDeque<DotPrice>>()
            .unwrap_or_default()
            .unwrap_or_default();

        debug::info!("cached dot price[{}]: {:?}", dot_info.len(), dot_info);

        // Since off-chain storage can be accessed by off-chain workers from multiple runs, it is important to lock
        //   it before doing heavy computations or write operations.
        // ref: https://substrate.dev/rustdocs/v2.0.0-rc3/sp_runtime/offchain/storage_lock/index.html
        //
        // There are four ways of defining a lock:
        //   1) `new` - lock with default time and block exipration
        //   2) `with_deadline` - lock with default block but custom time expiration
        //   3) `with_block_deadline` - lock with default time but custom block expiration
        //   4) `with_block_and_time_deadline` - lock with custom time and block expiration
        // Here we choose the most custom one for demonstration purpose.
        let mut lock = StorageLock::<BlockAndTime<Self>>::with_block_and_time_deadline(
            b"offchain-demo::lock",
            LOCK_BLOCK_EXPIRATION,
            rt_offchain::Duration::from_millis(LOCK_TIMEOUT_EXPIRATION),
        );

        // We try to acquire the lock here. If failed, we know the `fetch_n_parse` part inside is being
        //   executed by previous run of ocw, so the function just returns.
        // ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/storage_lock/struct.StorageLock.html#method.try_lock
        if let Ok(_guard) = lock.try_lock() {
            match Self::fetch_dotprice_parse() {
                Ok(dotprice_info) => {
                    let price = (str::from_utf8(&dotprice_info.data.price_usd)
                        .unwrap()
                        .parse::<f64>()
                        .unwrap()
                        * 1000.0) as u32;

                    if dot_info.len() == NUM_VEC_LEN {
                        let _ = dot_info.pop_front();
                    }

                    dot_info.push_back(dotprice_info);
                    s_info.set(&dot_info);
                    debug::info!("cache new dot price[{}]: {:?}", dot_info.len(), dot_info);

                    let _ = match block_number {
                        0 => Self::offchain_signed_tx(price),
                        1 => Self::offchain_unsigned_tx(price),
                        2 => Self::offchain_unsigned_tx_signed_payload(price),
                        _ => Err(Error::<T>::UnknownOffchainMux),
                    };
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    /// Append a new number to the tail of the list, removing an element from the head if reaching
    ///   the bounded length.
    fn append_or_replace_dotprice(dotprice: u32) {
        DotPrices::mutate(|dotprices| {
            if dotprices.len() == NUM_VEC_LEN {
                let _ = dotprices.pop_front();
            }
            dotprices.push_back(dotprice);
            debug::info!("DotPrices vector[{}]: {:?}", dotprices.len(), dotprices);
        });
    }

    /// Fetch from remote and deserialize the JSON to a struct
    fn fetch_dotprice_parse() -> Result<DotPrice, Error<T>> {
        let resp_bytes =
            Self::fetch_from_remote(HTTP_REMOTE_REQUEST_DOTPRICE, "").map_err(|e| {
                debug::error!("fetch_from_remote error: {:?}", e);
                <Error<T>>::HttpFetchingError
            })?;

        let resp_str = str::from_utf8(&resp_bytes).map_err(|_| <Error<T>>::HttpFetchingError)?;
        // Print out our fetched JSON string
        debug::info!("resp_str: {}", resp_str);

        // Deserializing JSON to struct, thanks to `serde` and `serde_derive`
        let dotprice_info: DotPrice =
            serde_json::from_str(&resp_str).map_err(|_| <Error<T>>::HttpFetchingError)?;

        debug::info!("dotprice: {:?}", dotprice_info);

        Ok(dotprice_info)
    }

    /// This function uses the `offchain::http` API to query the remote github information,
    ///   and returns the JSON response as vector of bytes.
    fn fetch_from_remote(url: &str, agent: &str) -> Result<Vec<u8>, Error<T>> {
        debug::info!("sending request to: {}", url);

        // Initiate an external HTTP GET request. This is using high-level wrappers from `sp_runtime`.
        let request = rt_offchain::http::Request::get(url);

        // Keeping the offchain worker execution time reasonable, so limiting the call to be within 3s.
        let timeout = sp_io::offchain::timestamp()
            .add(rt_offchain::Duration::from_millis(FETCH_TIMEOUT_PERIOD));

        let pending: rt_offchain::http::PendingRequest;
        // For github API request, we also need to specify `user-agent` in http request header.
        //   See: https://developer.github.com/v3/#user-agent-required
        if agent != "" {
            pending = request
                .add_header("User-Agent", agent)
                .deadline(timeout) // Setting the timeout time
                .send() // Sending the request out by the host
                .map_err(|_| <Error<T>>::HttpSendingError)?;
        } else {
            pending = request
                .deadline(timeout) // Setting the timeout time
                .send() // Sending the request out by the host
                .map_err(|_| <Error<T>>::HttpSendingError)?;
        }

        // By default, the http request is async from the runtime perspective. So we are asking the
        //   runtime to wait here.
        // The returning value here is a `Result` of `Result`, so we are unwrapping it twice by two `?`
        //   ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/http/struct.PendingRequest.html#method.try_wait
        let response = pending
            .try_wait(timeout)
            .map_err(|_| <Error<T>>::HttpFetchingError)?
            .map_err(|_| <Error<T>>::HttpFetchingError)?;

        if response.code != 200 {
            debug::error!("Unexpected http request status code: {}", response.code);
            return Err(<Error<T>>::HttpFetchingError);
        }

        // Next we fully read the response body and collect it to a vector of bytes.
        Ok(response.body().collect::<Vec<u8>>())
    }

    fn offchain_signed_tx(dotprice: u32) -> Result<(), Error<T>> {
        // We retrieve a signer and check if it is valid.
        //   Since this pallet only has one key in the keystore. We use `any_account()1 to
        //   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
        //   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
        let signer = Signer::<T, T::AuthorityId>::any_account();

        // `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
        //   - `None`: no account is available for sending transaction
        //   - `Some((account, Ok(())))`: transaction is successfully sent
        //   - `Some((account, Err(())))`: error occured when sending the transaction
        let result = signer.send_signed_transaction(|_acct|
			// This is the on-chain function
			Call::submit_dotprice_signed(dotprice));

        // Display error if the signed tx fails.
        if let Some((acc, res)) = result {
            if res.is_err() {
                debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
                return Err(<Error<T>>::OffchainSignedTxError);
            }
            // Transaction is sent successfully
            return Ok(());
        }

        // The case of `None`: no account is available for sending
        debug::error!("No local account available");
        Err(<Error<T>>::NoLocalAcctForSigning)
    }

    fn offchain_unsigned_tx(dotprice: u32) -> Result<(), Error<T>> {
        let call = Call::submit_dotprice_unsigned(dotprice);

        // `submit_unsigned_transaction` returns a type of `Result<(), ()>`
        //   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.SubmitTransaction.html#method.submit_unsigned_transaction
        SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()).map_err(|_| {
            debug::error!("Failed in offchain_unsigned_tx");
            <Error<T>>::OffchainUnsignedTxError
        })
    }

    fn offchain_unsigned_tx_signed_payload(dotprice: u32) -> Result<(), Error<T>> {
        // Retrieve the signer to sign the payload
        let signer = Signer::<T, T::AuthorityId>::any_account();

        // `send_unsigned_transaction` is returning a type of `Option<(Account<T>, Result<(), ()>)>`.
        //   Similar to `send_signed_transaction`, they account for:
        //   - `None`: no account is available for sending transaction
        //   - `Some((account, Ok(())))`: transaction is successfully sent
        //   - `Some((account, Err(())))`: error occured when sending the transaction
        if let Some((_, res)) = signer.send_unsigned_transaction(
            |acct| Payload {
                dotprice,
                public: acct.public.clone(),
            },
            Call::submit_dotprice_unsigned_with_signed_payload,
        ) {
            return res.map_err(|_| {
                debug::error!("Failed in offchain_unsigned_tx_signed_payload");
                <Error<T>>::OffchainUnsignedTxSignedPayloadError
            });
        }

        // The case of `None`: no account is available for sending
        debug::error!("No local account available");
        Err(<Error<T>>::NoLocalAcctForSigning)
    }
}

impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
    type Call = Call<T>;

    fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
        let valid_tx = |provide| {
            ValidTransaction::with_tag_prefix("ocw-demo")
                .priority(UNSIGNED_TXS_PRIORITY)
                .and_provides([&provide])
                .longevity(3)
                .propagate(true)
                .build()
        };

        match call {
            Call::submit_dotprice_unsigned(_dotprice) => {
                valid_tx(b"submit_dotprice_unsigned".to_vec())
            }
            Call::submit_dotprice_unsigned_with_signed_payload(ref payload, ref signature) => {
                if !SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone()) {
                    return InvalidTransaction::BadProof.into();
                }
                valid_tx(b"submit_dotprice_unsigned_with_signed_payload".to_vec())
            }
            _ => InvalidTransaction::Call.into(),
        }
    }
}

impl<T: Trait> rt_offchain::storage_lock::BlockNumberProvider for Module<T> {
    type BlockNumber = T::BlockNumber;
    fn current_block_number() -> Self::BlockNumber {
        <frame_system::Module<T>>::block_number()
    }
}
