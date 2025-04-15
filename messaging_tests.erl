-module(messaging_tests).
-include_lib("eunit/include/eunit.hrl").

%% Quiz app tests
quiz_app_test_() ->
    [
     {"Test Quiz app branching logic",
      fun() ->
              % Launch quiz app
              ?assertEqual(ok, messaging:launch_app(quiz_app, intro)),
              
              % Test the branching logic
              ?assertEqual(ok, messaging:interact(quiz_app, "1")), % Languages category
              ?assertEqual(ok, messaging:interact(quiz_app, "1")), % Easy question
              ?assertEqual(ok, messaging:interact(quiz_app, "2")), % Correct answer (Java)
              ?assertEqual(ok, messaging:interact(quiz_app, "2")), % Back to categories
              
              % Try another branch
              ?assertEqual(ok, messaging:interact(quiz_app, "2")), % Databases
              ?assertEqual(ok, messaging:interact(quiz_app, "1")), % SQL question
              ?assertEqual(ok, messaging:interact(quiz_app, "2")), % Correct answer (MongoDB)
              
              % Show history
              ?assertEqual(ok, messaging:show_history(quiz_app))
      end}
    ].

%% Security tests
security_test_() ->
    [
     {"Test user registration and authentication",
      fun() ->
              %% Register a user
              {ok, UserId} = messaging:register_user("testuser", "password123"),
              
              %% Test login
              ?assertMatch({ok, _}, messaging:login_user("testuser", "password123")),
              ?assertMatch({error, invalid_credentials}, messaging:login_user("testuser", "wrongpass")),
              ?assertMatch({error, user_not_found}, messaging:login_user("nonexistent", "anything")),
              
              %% Test session management
              ?assertEqual(ok, messaging:launch_app(example_app, intro)),
              {ok, SessionId, Token} = messaging:start_session(UserId, example_app),
              
              %` Interact securely
              ?assertMatch({ok, _}, messaging:secure_interact(SessionId, Token, "1")),
              
              % End session
              ?assertEqual(ok, messaging:end_session(SessionId))
      end}
    ].
