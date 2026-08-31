# Backward compatibility wrapper: redirects imports from deprecated app.config to the relocated app.core.config layer.
# All production code should migrate to importing from app.core.config directly.
from app.core.config import settings
