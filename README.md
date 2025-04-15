# Coding Challenge

## Code App
**quiz_app** - A quiz app with multiple categories (Languages, Databases, Web) and branching logic


## How to Run

### Compilation
```erl
c(messaging).
```

### Run Quiz App
```erl
messaging:launch_app(quiz_app, intro).
messaging:interact(quiz_app, "1").  % Choose Languages
messaging:interact(quiz_app, "1").  % Choose Easy question
messaging:interact(quiz_app, "2").  % Answer "Java"
messaging:show_history(quiz_app).
```

### Run with Security
```erl
{ok, UserId} = messaging:register_user("testuser", "password123").
{ok, UserId} = messaging:login_user("testuser", "password123").
messaging:launch_app(quiz_app, intro).
{ok, SessionId, Token} = messaging:start_session(UserId, quiz_app).
{ok, NewToken} = messaging:secure_interact(SessionId, Token, "1").
% Use the new token for subsequent interactions
```

## Testing

Run the test suite with:
```erl
c(messaging_tests).
eunit:test(messaging_tests).
```
