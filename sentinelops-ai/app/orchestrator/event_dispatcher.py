from sqlalchemy import select

from app.agents.github.push_agent import PushAgent
from app.database import SessionLocal
from app.database.models.github_event import GitHubEvent


class EventDispatcher:

    def __init__(self):

        self.push_agent = PushAgent()

    def dispatch(self):

        db = SessionLocal()

        try:

            events = db.scalars(
                select(GitHubEvent).where(
                    GitHubEvent.processed == False
                )
            ).all()

            for event in events:

                if event.event_type == "push":

                    self.push_agent.handle(event)

                event.processed = True

            db.commit()

        finally:

            db.close()