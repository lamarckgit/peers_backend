from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from contextlib import contextmanager

class Database:
    def __init__(self, database_url: str, pool_size=10, max_overflow=20, echo=False):
        self.engine = create_engine(
            database_url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            echo=echo
        )
        self.SessionFactory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)

    def create_session(self) -> Session:
        """Create a new SQLAlchemy session."""
        return self.SessionFactory()

    @contextmanager
    def session_scope(self):
        """Provide a transactional scope around a series of operations."""
        db = self.create_session()
        try:
            yield db
            db.commit()
        except SQLAlchemyError as e:
            db.rollback()
            raise e
        finally:
            db.close()

    def get_engine(self):
        """Expose the engine for raw connections if needed."""
        return self.engine

