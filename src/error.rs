use crdts::Dot;
use sn_data_types::{Credit, Debit, Error as DtError, Money, PublicKey};
use thiserror::Error;
#[derive(Error, Debug)]
#[non_exhaustive]
/// SafeNetwork Transfers error type
pub enum Error {
    /// Missing sender actor
    #[error("Sender missing from actors")]
    MissingSender,
    /// Missing recipient
    #[error("Recipient missing from actors")]
    MissingRecipient,
    /// Missing Replica Group
    #[error("ReplicaGroup is missing")]
    MissingReplicaGroup,

    /// Sender and receiver are the same
    #[error("Sender and recipient are the same")]
    SameSenderAndRecipient,

    /// A debit is awaiting completion. A new debit cannot be started.
    #[error("Current pending debit has not been completed")]
    DebitPending,

    /// The provided PublicKey does not correlate with any key in the section chain history.
    #[error("PublicKey provided by the transfer was never a part of the section chain.")]
    SectionKeyNeverExisted,

    /// The proposed debit has already been seen, or is not the next expected debit
    #[error("Debit already proposed or out of order")]
    DebitProposed,
    /// Credit Id and debit Id do not match
    #[error("Credit and debit ids do not match")]
    CreditDebitIdMismatch,
    /// Credit and debits do not have the same value
    #[error("Credit and debit value do not match")]
    CreditDebitValueMismatch,
    /// This is not the correct actor to validate
    #[error("Validation not intended for this actor")]
    WrongValidationActor,
    /// No pending transfer could be found awaiting accumulation
    #[error("Could not find the expected transfer id among accumulating validations")]
    PendingTransferNotFound,
    /// Validation is not for this actor
    #[error("Validation not expected at this actor {0:?}")]
    NoSetForDebitId(Dot<PublicKey>),
    /// Transer is not for this actor
    #[error("Transfer not expected for this actor {0:?}")]
    NoSetForTransferId(Dot<PublicKey>),

    /// Proposed operation is not the next in sequence. The debit op should be current actor count + 1
    #[error("Operation out of order: debit's counter is '{0}', current actor counter is '{1}'")]
    OperationOutOfOrder(u64, u64),

    /// This account has not seen any debits yet. Sent debit should be 0 but was not.
    #[error("Operation out of order debit counter should be 0")]
    ShouldBeInitialOperation,
    /// No credits or debits were found to sync
    #[error("No credits or debits found to sync to actor")]
    NothingToSync,
    /// 0-value transfers are invalid
    #[error("Transfer amount must be greater than zero")]
    ZeroValueTransfer,
    /// The validation has already been received
    #[error("Validation already received")]
    ValidatedAlready,

    /// Debit is not from this wallet
    #[error("Debit is not from wallet {0}. Debit: {1:?}")]
    DebitDoesNotBelong(PublicKey, Debit),
    /// Credit is not from this wallet
    #[error("Credit is not from wallet {0}. Credit: {1:?}")]
    CreditDoesNotBelong(PublicKey, Credit),
    /// Subtracting this transfer would cause an overlow
    #[error("Overlow when subtracting {0} from balance of: {1}")]
    SubtractionOverflow(Money, Money),
    /// Adding this transfer would cause an overflow
    #[error("Overlow when adding balance {0} and credit of: {1}")]
    AdditionOverflow(Money, Money),
    /// Unexpected outcome
    // TODO: clarify this...
    #[error("Unexpected outcome")]
    UnexpectedOutcome,

    /// Wallet not found
    #[error("Wallet not found locally. The following debit was the cause: {0:?}")]
    WalletNotFound(Debit),
    /// Signature shares are insufficient for BLS aggregation
    #[error("Could not aggregate with given signature shares")]
    CannotAggregate,

    /// Signature is not valid
    #[error("Signature is not valid")]
    InvalidSignature,

    /// Operation is not valid
    #[error("Operation is not valid")]
    InvalidOperation,

    /// Insufficient coins.
    #[error("Insufficient balance to complete this operation")]
    InsufficientBalance,
    /// Inexistent sender balance.
    #[error("No such sender key balance")]
    NoSuchSender,
    /// Inexistent recipient balance. Currently only thrown during network genesis
    #[error("No such recipient key balance")]
    NoSuchRecipient,

    /// Coin balance already exists.
    #[error("Key already exists")]
    KeyExists,

    /// Other sn_data_types errors
    #[error(transparent)]
    NetworkDataError(#[from] DtError),

    /// Serialisation
    #[error("Serialisation error. {0}")]
    Serialisation(String),
}
