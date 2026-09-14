# Porting

Board-specific code stays outside the portable security-key crates. New board
profiles belong under `boards/` and should depend on the HAL boundary rather
than exposing hardware details to the core domain.
