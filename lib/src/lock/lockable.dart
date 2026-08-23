// Intent: Minimal lock contract so lifecycle/posture controllers are testable
// without a full VaultService. VaultService implements this.
abstract class Lockable {
  Future<void> lock();
}