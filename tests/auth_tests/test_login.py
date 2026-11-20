from django.contrib import auth
from django.contrib.auth import aget_user, get_user, signals
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.http import HttpRequest
from django.test import TestCase, override_settings


class TestLogin(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username="testuser", password="password")

    def setUp(self):
        self.request = HttpRequest()
        self.request.session = self.client.session

    def test_user_login(self):
        auth.login(self.request, self.user)
        self.assertEqual(self.request.session[auth.SESSION_KEY], str(self.user.pk))

    def test_inactive_user(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        auth.login(self.request, self.user)
        self.assertEqual(self.request.session[auth.SESSION_KEY], str(self.user.pk))

    def test_without_user(self):
        with self.assertRaisesMessage(
            AttributeError,
            "'NoneType' object has no attribute 'get_session_auth_hash'",
        ):
            auth.login(self.request, None)


class FirstBackend(ModelBackend):
    get_user_calls = 0

    def get_user(self, user_id):
        type(self).get_user_calls += 1
        return super().get_user(user_id)

    async def aget_user(self, user_id):
        type(self).get_user_calls += 1
        return await super().aget_user(user_id)


class SecondBackend(ModelBackend):
    get_user_calls = 0

    def get_user(self, user_id):
        type(self).get_user_calls += 1
        return super().get_user(user_id)

    async def aget_user(self, user_id):
        type(self).get_user_calls += 1
        return await super().aget_user(user_id)


class RecordingSessionStore(SessionStore):
    """
    A database session store that records when sessions are created and
    deleted, to check the order of the operations replacing a session.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = []

    def create(self):
        super().create()
        self.events.append(("create", self.session_key))

    def delete(self, session_key=None):
        super().delete(session_key)
        self.events.append(("delete", session_key))


@override_settings(
    AUTHENTICATION_BACKENDS=[
        "auth_tests.test_login.FirstBackend",
        "auth_tests.test_login.SecondBackend",
    ]
)
class LoginBackendSessionTests(TestCase):
    first_backend = "auth_tests.test_login.FirstBackend"
    second_backend = "auth_tests.test_login.SecondBackend"

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username="testuser", password="password")

    def setUp(self):
        FirstBackend.get_user_calls = 0
        SecondBackend.get_user_calls = 0

    def stored_session(self, session_key):
        return SessionStore(session_key)

    def new_request(self, session=None):
        request = HttpRequest()
        request.session = session if session is not None else SessionStore()
        return request

    def test_anonymous_login_keeps_session_data(self):
        request = self.new_request()
        request.session["anonymous"] = "kept"
        request.session.save()
        anonymous_key = request.session.session_key

        auth.login(request, self.user, backend=self.first_backend)
        request.session.save()

        self.assertNotEqual(request.session.session_key, anonymous_key)
        self.assertEqual(request.session["anonymous"], "kept")
        self.assertEqual(request.session[auth.BACKEND_SESSION_KEY], self.first_backend)
        self.assertEqual(
            request.session[auth.HASH_SESSION_KEY], self.user.get_session_auth_hash()
        )
        self.assertFalse(Session.objects.filter(session_key=anonymous_key).exists())

    def test_recurring_login_keeps_session_data_and_key(self):
        request = self.new_request()
        request.session["anonymous"] = "kept"
        auth.login(request, self.user, backend=self.first_backend)
        request.session.save()
        first_key = request.session.session_key

        request.session["business"] = "kept"
        request.session.save()

        auth.login(request, self.user, backend=self.first_backend)
        request.session.save()

        self.assertEqual(request.session.session_key, first_key)
        self.assertEqual(request.session["anonymous"], "kept")
        self.assertEqual(request.session["business"], "kept")
        self.assertTrue(Session.objects.filter(session_key=first_key).exists())

    def test_switching_backend_starts_new_session(self):
        request = self.new_request()
        request.session["anonymous"] = "kept"
        auth.login(request, self.user, backend=self.first_backend)
        request.session["business"] = "dropped"
        request.session.save()
        first_key = request.session.session_key

        auth.login(request, self.user, backend=self.second_backend)
        request.session.save()
        new_key = request.session.session_key

        # The session record is new: the old identifier is gone and the old
        # data was not carried over.
        self.assertNotEqual(new_key, first_key)
        self.assertFalse(Session.objects.filter(session_key=first_key).exists())
        stored_new = self.stored_session(new_key)
        self.assertEqual(stored_new[auth.SESSION_KEY], str(self.user.pk))
        self.assertEqual(stored_new[auth.BACKEND_SESSION_KEY], self.second_backend)
        self.assertEqual(
            stored_new[auth.HASH_SESSION_KEY], self.user.get_session_auth_hash()
        )
        self.assertNotIn("business", stored_new)
        self.assertNotIn("anonymous", stored_new)
        self.assertNotIn("business", request.session)
        self.assertNotIn("anonymous", request.session)

        # Reading the authenticated user back uses the new backend only.
        read_back_request = self.new_request(self.stored_session(new_key))
        self.assertEqual(get_user(read_back_request), self.user)
        self.assertEqual(SecondBackend.get_user_calls, 1)
        self.assertEqual(FirstBackend.get_user_calls, 0)

    def test_switching_backend_creates_new_session_before_deleting_old_one(self):
        request = self.new_request(RecordingSessionStore())
        auth.login(request, self.user, backend=self.first_backend)
        request.session.save()
        old_key = request.session.session_key
        request.session["business"] = "dropped"
        request.session.save()
        request.session.events.clear()

        auth.login(request, self.user, backend=self.second_backend)
        request.session.save()

        events = request.session.events
        create_index = events.index(("create", request.session.session_key))
        delete_index = events.index(("delete", old_key))
        self.assertLess(create_index, delete_index)
        self.assertFalse(Session.objects.filter(session_key=old_key).exists())

    def test_backend_switch_notifies_once_with_new_backend(self):
        request = self.new_request()
        auth.login(request, self.user, backend=self.first_backend)
        request.session.save()
        first_key = request.session.session_key

        received = []

        def receiver(sender, request, user, **kwargs):
            received.append(
                (
                    user.pk,
                    request.session.get(auth.BACKEND_SESSION_KEY),
                    request.session.session_key,
                )
            )

        signals.user_logged_in.connect(receiver)
        self.addCleanup(signals.user_logged_in.disconnect, receiver)

        auth.login(request, self.user, backend=self.second_backend)
        request.session.save()
        new_key = request.session.session_key

        # The observer is notified once and already sees the switched backend
        # in the replacement session.
        self.assertNotEqual(new_key, first_key)
        self.assertEqual(received, [(self.user.pk, self.second_backend, new_key)])

    def test_backend_selection_failure_keeps_current_session(self):
        other_user = User.objects.create_user(username="otheruser", password="password")
        request = self.new_request()
        auth.login(request, self.user, backend=self.first_backend)
        request.session.save()
        session_key = request.session.session_key
        request.session["business"] = "kept"
        request.session.save()

        # Evidence that the current session was valid before the failed login.
        self.assertEqual(get_user(request), self.user)

        # A user without a ``backend`` attribute and multiple configured
        # backends makes the backend selection fail. This user is not the one
        # the session belongs to, so a session replacement must not happen
        # before the configuration error is reported.
        self.assertFalse(hasattr(other_user, "backend"))
        message = (
            "You have multiple authentication backends configured and "
            "therefore must provide the `backend` argument or set the "
            "`backend` attribute on the user."
        )
        with self.assertRaisesMessage(ValueError, message):
            auth.login(request, other_user)

        # The session wasn't cleared before reporting the configuration error.
        self.assertEqual(request.session.session_key, session_key)
        self.assertEqual(request.session[auth.SESSION_KEY], str(self.user.pk))
        self.assertEqual(request.session[auth.BACKEND_SESSION_KEY], self.first_backend)
        self.assertEqual(request.session["business"], "kept")
        stored = self.stored_session(session_key)
        self.assertEqual(stored[auth.SESSION_KEY], str(self.user.pk))
        self.assertEqual(stored[auth.BACKEND_SESSION_KEY], self.first_backend)
        self.assertEqual(stored["business"], "kept")
        self.assertEqual(get_user(self.new_request(stored)), self.user)

        # The anonymous session is also left untouched by a failed login.
        anonymous_request = self.new_request()
        anonymous_request.session["anonymous"] = "kept"
        anonymous_request.session.save()
        anonymous_key = anonymous_request.session.session_key
        with self.assertRaisesMessage(ValueError, message):
            auth.login(anonymous_request, other_user)
        self.assertEqual(anonymous_request.session.session_key, anonymous_key)
        self.assertEqual(anonymous_request.session["anonymous"], "kept")

    async def test_async_login_decisions_match_sync(self):
        request = self.new_request(await self.client.asession())
        await request.session.aset("anonymous", "kept")
        await request.session.asave()
        anonymous_key = request.session.session_key

        # Anonymous first login keeps the session data.
        await auth.alogin(request, self.user, backend=self.first_backend)
        await request.session.asave()
        first_key = request.session.session_key
        self.assertNotEqual(first_key, anonymous_key)
        self.assertEqual(await request.session.aget("anonymous"), "kept")
        self.assertFalse(
            await Session.objects.filter(session_key=anonymous_key).aexists()
        )

        # Recurring login with the same user, auth hash, and backend keeps the
        # session and its data.
        await request.session.aset("business", "kept")
        await request.session.asave()
        await auth.alogin(request, self.user, backend=self.first_backend)
        await request.session.asave()
        self.assertEqual(request.session.session_key, first_key)
        self.assertEqual(await request.session.aget("business"), "kept")

        # Switching the backend starts a new session without the old data.
        received = []

        def receiver(sender, request, user, **kwargs):
            received.append(
                (
                    user.pk,
                    request.session.get(auth.BACKEND_SESSION_KEY),
                    request.session.session_key,
                )
            )

        signals.user_logged_in.connect(receiver)
        self.addCleanup(signals.user_logged_in.disconnect, receiver)

        await auth.alogin(request, self.user, backend=self.second_backend)
        await request.session.asave()
        new_key = request.session.session_key
        self.assertNotEqual(new_key, first_key)
        self.assertFalse(await Session.objects.filter(session_key=first_key).aexists())
        self.assertTrue(await Session.objects.filter(session_key=new_key).aexists())
        self.assertEqual(
            await request.session.aget(auth.BACKEND_SESSION_KEY), self.second_backend
        )
        self.assertEqual(
            await request.session.aget(auth.HASH_SESSION_KEY),
            self.user.get_session_auth_hash(),
        )
        self.assertIsNone(await request.session.aget("business"))
        self.assertIsNone(await request.session.aget("anonymous"))
        self.assertEqual(received, [(self.user.pk, self.second_backend, new_key)])

        # Reading the authenticated user back uses the new backend only.
        read_back_request = self.new_request(self.stored_session(new_key))
        self.assertEqual(await aget_user(read_back_request), self.user)
        self.assertEqual(SecondBackend.get_user_calls, 1)
        self.assertEqual(FirstBackend.get_user_calls, 0)

        # Evidence the session authenticated before the failed login.
        read_back_before = await aget_user(request)
        self.assertEqual(read_back_before.pk, self.user.pk)

        # A failed backend selection leaves the current session untouched.
        other_user = await User.objects.acreate_user(
            username="otheruser", password="password"
        )
        self.assertFalse(hasattr(other_user, "backend"))
        message = (
            "You have multiple authentication backends configured and "
            "therefore must provide the `backend` argument or set the "
            "`backend` attribute on the user."
        )
        with self.assertRaisesMessage(ValueError, message):
            await auth.alogin(request, other_user)
        self.assertEqual(request.session.session_key, new_key)
        self.assertEqual(
            await request.session.aget(auth.BACKEND_SESSION_KEY), self.second_backend
        )
        self.assertEqual(
            await request.session.aget(auth.SESSION_KEY), str(self.user.pk)
        )
        self.assertTrue(await Session.objects.filter(session_key=new_key).aexists())
        self.assertEqual(await aget_user(request), read_back_before)

        # An anonymous session is also left untouched by a failed login.
        anonymous_request = self.new_request(await self.client.asession())
        await anonymous_request.session.aset("anonymous", "kept")
        await anonymous_request.session.asave()
        anonymous_key = anonymous_request.session.session_key
        with self.assertRaisesMessage(ValueError, message):
            await auth.alogin(anonymous_request, other_user)
        self.assertEqual(anonymous_request.session.session_key, anonymous_key)
        self.assertEqual(await anonymous_request.session.aget("anonymous"), "kept")
