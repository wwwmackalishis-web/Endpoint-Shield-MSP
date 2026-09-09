from database import engine, Base
import models

def init_db():
    Base.metadata.create_all(bind=engine, checkfirst=True)

if __name__ == "__main__":
    init_db()
