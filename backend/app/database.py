# Backward compatibility wrapper: redirects imports from deprecated app.database to the relocated app.db.mongodb layer.
# All production code should migrate to importing from app.db.mongodb directly.
from app.db.mongodb import db_helper
