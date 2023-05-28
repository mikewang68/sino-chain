pub enum AccessType {
    PrimaryOnly,
    PrimaryOnlyForMaintenance, // this indicates no compaction
    TryPrimaryThenSecondary,
}