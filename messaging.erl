-module(messaging).

-export([apps/0, run_app/4, launch_app/2, interact/2, show_state/1, show_history/1, 
         save_state/1, load_state/1, launch_app_with_history/2,
         register_user/2, login_user/2, secure_interact/3, start_session/2, end_session/1,
         initialize_question_versions/2, store_question_version/5, get_question_versions/2, 
         get_question_version/3, update_question/4, find_question/2, get_latest_version/2]).

-record(app_state, {msg, logic}).
-record(question, {id, msg, opts = [], anchor = []}).
-record(user, 
    {username, 
    password_hash, 
    user_id, 
    sessions=[]}).
-record(session, 
    {session_id, 
    user_id, 
    app_name, 
    timestamp, 
    token}).
-record(question_metadata, 
    {app_name, 
     question_id, 
     version, 
     timestamp, 
     content, 
     author}).


-define(USERS_TABLE, users_table).
-define(SESSIONS_TABLE, sessions_table).
-define(QUESTION_HISTORY_TABLE, question_history_table).
-define(SESSION_TIMEOUT, 300). % 5 minutes timeout (in seconds)

% Initialize secure environment
init_security() ->
    % Create ETS tables if they don't exist
    case ets:info(?USERS_TABLE) of
        undefined -> ets:new(?USERS_TABLE, [set, named_table, {keypos, #user.username}]);
        _ -> ok
    end,
    
    case ets:info(?SESSIONS_TABLE) of
        undefined -> ets:new(?SESSIONS_TABLE, [set, named_table, {keypos, #session.session_id}]);
        _ -> ok
    end,
    
    case ets:info(?QUESTION_HISTORY_TABLE) of
        undefined -> ets:new(?QUESTION_HISTORY_TABLE, [bag, named_table]);
        _ -> ok
    end,
    
    % Start session cleaner process
    spawn(fun() -> session_cleaner() end),
    ok.

% Session cleaner process to remove expired sessions
session_cleaner() ->
    timer:sleep(60000), % Run every minute
    CurrentTime = os:system_time(seconds),
    ExpiredTime = CurrentTime - ?SESSION_TIMEOUT,
    
    % Find expired sessions
    ExpiredSessions = ets:foldl(
        fun(Session, Acc) ->
            #session{session_id = SessId, timestamp = Timestamp} = Session,
            case Timestamp < ExpiredTime of
                true -> [SessId | Acc];
                false -> Acc
            end
        end, [], ?SESSIONS_TABLE),
    
    % Delete expired sessions
    [ets:delete(?SESSIONS_TABLE, SessId) || SessId <- ExpiredSessions],
    
    % If any sessions were expired, log it
    case ExpiredSessions of
        [] -> ok;
        _ -> io:format("Cleaned ~p expired sessions~n", [length(ExpiredSessions)])
    end,
    
    % Continue cleaning
    session_cleaner().

% Generate a secure random token
generate_token() ->
    Bytes = crypto:strong_rand_bytes(32),
    base64:encode(Bytes).

% Hash a password
hash_password(Password) ->
    Salt = crypto:strong_rand_bytes(16),
    Hash = crypto:hash(sha256, <<Salt/binary, Password/binary>>),
    base64:encode(<<Salt/binary, Hash/binary>>).

% Verify a password against a hash
verify_password(Password, StoredHash) ->
    DecodedHash = base64:decode(StoredHash),
    <<Salt:16/binary, Hash/binary>> = DecodedHash,
    CalculatedHash = crypto:hash(sha256, <<Salt/binary, Password/binary>>),
    Hash =:= CalculatedHash.

% Register a new user
register_user(Username, Password) ->
    % Initialize security if not already done
    init_security(),
    
    % Create a unique user ID
    UserId = list_to_binary(io_lib:format("user_~p", [os:system_time(millisecond)])),
    
    % Hash the password
    PasswordHash = hash_password(list_to_binary(Password)),
    
    % Create user record
    User = #user{
        username = Username,
        password_hash = PasswordHash,
        user_id = UserId,
        sessions = []
    },
    
    % Store in ETS table
    case ets:insert_new(?USERS_TABLE, User) of
        true -> 
            io:format("User ~p registered successfully~n", [Username]),
            {ok, UserId};
        false -> 
            {error, username_taken}
    end.

% Login a user
login_user(Username, Password) ->
    % Initialize security if not already done
    init_security(),
    
    case ets:lookup(?USERS_TABLE, Username) of
        [User] ->
            #user{password_hash = StoredHash, user_id = UserId} = User,
            case verify_password(list_to_binary(Password), StoredHash) of
                true -> 
                    {ok, UserId};
                false -> 
                    {error, invalid_credentials}
            end;
        [] ->
            {error, user_not_found}
    end.

% Start a session for a user with an app
start_session(UserId, AppName) ->
    % Initialize security if not already done
    init_security(),
    
    % Generate session ID and authentication token
    SessionId = list_to_binary(io_lib:format("session_~p", [os:system_time(millisecond)])),
    Token = generate_token(),
    CurrentTime = os:system_time(seconds),
    
    % Create session record
    Session = #session{
        session_id = SessionId,
        user_id = UserId,
        app_name = AppName,
        timestamp = CurrentTime,
        token = Token
    },
    
    % Store in sessions table
    ets:insert(?SESSIONS_TABLE, Session),
    
    % Return session info
    {ok, SessionId, Token}.

% End a session
end_session(SessionId) ->
    ets:delete(?SESSIONS_TABLE, SessionId),
    ok.

% Update session timestamp (keep session alive)
touch_session(SessionId, Token) ->
    case ets:lookup(?SESSIONS_TABLE, SessionId) of
        [Session] ->
            #session{token = StoredToken} = Session,
            case StoredToken =:= Token of
                true ->
                    % Update timestamp
                    NewSession = Session#session{timestamp = os:system_time(seconds)},
                    ets:insert(?SESSIONS_TABLE, NewSession),
                    ok;
                false ->
                    {error, invalid_token}
            end;
        [] ->
            {error, session_not_found}
    end.

% Interact with an app securely
secure_interact(SessionId, Token, Msg) ->
    % First verify and update session
    case touch_session(SessionId, Token) of
        ok ->
            % Get session details
            [Session] = ets:lookup(?SESSIONS_TABLE, SessionId),
            #session{app_name = AppName} = Session,
            
            % Pass the message to the app
            interact(AppName, Msg),
            
            % Return success with a new token for next interaction
            NewToken = generate_token(),
            NewSession = Session#session{token = NewToken, timestamp = os:system_time(seconds)},
            ets:insert(?SESSIONS_TABLE, NewSession),
            {ok, NewToken};
        Error ->
            Error
    end.

apps() ->
    [{example_app,

      [{intro, #app_state{msg = "Choose a topic: (1) Rice (2) Cotton",
                          logic = fun (Resp) -> case Resp of
                                                    "1" -> rice1;
                                                    "2" -> cotton1;
                                                    _Otherwise -> intro
                                                end
                                  end}},

       {rice1, #app_state{msg = "Rice is the seed of the grass species Oryza glaberrima or Oryza sativa.",
                          logic = fun (_) -> rice2 end}},

       {rice2, #app_state{msg = "As a cereal grain, it is the most widely consumed staple food for a large part of the world's human population, especially in Asia and Africa.",
                          logic = fun (_) -> rice3 end}},

       {rice3, #app_state{msg = "It is the agricultural commodity with the third-highest worldwide production, after sugarcane and maize.",
                          logic = fun (_) -> intro end}},

       {cotton1, #app_state{msg = "Cotton is a soft, fluffy staple fiber that grows in a boll, or protective case, around the seeds of the cotton plants of the genus Gossypium in the mallow family Malvaceae.",
                          logic = fun (_) -> cotton2 end}},

       {cotton2, #app_state{msg = "The fiber is almost pure cellulose. Under natural conditions, the cotton bolls will increase the dispersal of the seeds.",
                          logic = fun (_) -> intro end}}]

     },
     {survey_app,
      [#question{id = intro,
                 msg = "Choose a topic: (1) Rice (2) Cotton",
                 opts = ["1", "2"]},
       #question{id = rice1,
                 msg =
                     "Rice is the seed of the grass species Oryza glaberrima or Oryza "
                     "sativa. Choose a topic: (2) Rice2 (3) Rice3",
                 opts = ["2", "3"],
                 anchor = [{intro, "1"}]},
       #question{id = rice2,
                 msg =
                     "As a cereal grain, it is the most widely consumed staple food "
                     "for a large part of the world's human population, especially "
                     "in Asia and Africa.",
                 anchor = [{rice1, "2"}, {intro, "1"}]},
       #question{id = rice3,
                 msg =
                     "It is the agricultural commodity with the third-highest worldwide "
                     "production, after sugarcane and maize.",
                 anchor = [{rice1, "3"}, {intro, "1"}]},
       #question{id = cotton1,
                 msg =
                     "Cotton is a soft, fluffy staple fiber that grows in a boll, "
                     "or protective case, around the seeds of the cotton plants of "
                     "the genus Gossypium in the mallow family Malvaceae.",
                 anchor = [{intro, "2"}]},
       #question{id = cotton2,
                 msg =
                     "The fiber is almost pure cellulose. Under natural conditions, "
                     "the cotton bolls will increase the dispersal of the seeds.",
                 anchor = [{intro, "2"}]}]},
     {quiz_app,
      [{intro, #app_state{msg = "Welcome to the Programming Quiz! Choose a category: (1) Languages (2) Databases (3) Web",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_intro;
                                                  "2" -> databases_intro;
                                                  "3" -> web_intro;
                                                  _Otherwise -> intro
                                              end
                                 end}},
       {languages_intro, #app_state{msg = "Programming Languages: (1) Easy question (2) Hard question (3) Go back",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_easy;
                                                  "2" -> languages_hard;
                                                  "3" -> intro;
                                                  _Otherwise -> languages_intro
                                              end
                                 end}},
       {languages_easy, #app_state{msg = "What language is known for its garbage collection? (1) C (2) Java (3) Assembly",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_easy_wrong;
                                                  "2" -> languages_easy_correct;
                                                  "3" -> languages_easy_wrong;
                                                  _Otherwise -> languages_easy
                                              end
                                 end}},
       {languages_easy_correct, #app_state{msg = "Correct! Java has automatic garbage collection. (1) Another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> languages_easy_correct
                                              end
                                 end}},
       {languages_easy_wrong, #app_state{msg = "Incorrect. Java has automatic garbage collection. (1) Try another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> languages_easy_wrong
                                              end
                                 end}},
       {languages_hard, #app_state{msg = "Which of these is NOT a functional programming language? (1) Haskell (2) Erlang (3) Python",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_hard_wrong;
                                                  "2" -> languages_hard_wrong;
                                                  "3" -> languages_hard_correct;
                                                  _Otherwise -> languages_hard
                                              end
                                 end}},
       {languages_hard_correct, #app_state{msg = "Correct! While Python has functional features, it's primarily multi-paradigm. (1) Another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> languages_hard_correct
                                              end
                                 end}},
       {languages_hard_wrong, #app_state{msg = "Incorrect. Both Haskell and Erlang are functional programming languages. (1) Try another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> languages_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> languages_hard_wrong
                                              end
                                 end}},
       {databases_intro, #app_state{msg = "Database Questions: (1) SQL (2) NoSQL (3) Go back",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> sql_question;
                                                  "2" -> nosql_question;
                                                  "3" -> intro;
                                                  _Otherwise -> databases_intro
                                              end
                                 end}},
       {sql_question, #app_state{msg = "Which is NOT an SQL database? (1) PostgreSQL (2) MongoDB (3) MySQL",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> sql_wrong;
                                                  "2" -> sql_correct;
                                                  "3" -> sql_wrong;
                                                  _Otherwise -> sql_question
                                              end
                                 end}},
       {sql_correct, #app_state{msg = "Correct! MongoDB is a NoSQL database. (1) Another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> databases_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> sql_correct
                                              end
                                 end}},
       {sql_wrong, #app_state{msg = "Incorrect. MongoDB is a NoSQL database. (1) Try another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> databases_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> sql_wrong
                                              end
                                 end}},
       {nosql_question, #app_state{msg = "What type of NoSQL database is Redis? (1) Document (2) Key-Value (3) Graph",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> nosql_wrong;
                                                  "2" -> nosql_correct;
                                                  "3" -> nosql_wrong;
                                                  _Otherwise -> nosql_question
                                              end
                                 end}},
       {nosql_correct, #app_state{msg = "Correct! Redis is a key-value store. (1) Another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> databases_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> nosql_correct
                                              end
                                 end}},
       {nosql_wrong, #app_state{msg = "Incorrect. Redis is a key-value store. (1) Try another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> databases_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> nosql_wrong
                                              end
                                 end}},
       {web_intro, #app_state{msg = "Web Development: (1) Frontend (2) Backend (3) Go back",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> frontend_question;
                                                  "2" -> backend_question;
                                                  "3" -> intro;
                                                  _Otherwise -> web_intro
                                              end
                                 end}},
       {frontend_question, #app_state{msg = "Which is NOT a JavaScript framework? (1) React (2) Django (3) Vue",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> frontend_wrong;
                                                  "2" -> frontend_correct;
                                                  "3" -> frontend_wrong;
                                                  _Otherwise -> frontend_question
                                              end
                                 end}},
       {frontend_correct, #app_state{msg = "Correct! Django is a Python web framework. (1) Another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> web_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> frontend_correct
                                              end
                                 end}},
       {frontend_wrong, #app_state{msg = "Incorrect. Django is a Python web framework, not JavaScript. (1) Try another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> web_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> frontend_wrong
                                              end
                                 end}},
       {backend_question, #app_state{msg = "Which language is Node.js based on? (1) JavaScript (2) Python (3) Ruby",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> backend_correct;
                                                  "2" -> backend_wrong;
                                                  "3" -> backend_wrong;
                                                  _Otherwise -> backend_question
                                              end
                                 end}},
       {backend_correct, #app_state{msg = "Correct! Node.js uses JavaScript. (1) Another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> web_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> backend_correct
                                              end
                                 end}},
       {backend_wrong, #app_state{msg = "Incorrect. Node.js uses JavaScript. (1) Try another question (2) Back to categories",
                          logic = fun(Resp) -> case Resp of
                                                  "1" -> web_intro;
                                                  "2" -> intro;
                                                  _Otherwise -> backend_wrong
                                              end
                                 end}}
      ]}].

survey_app(AppName, [], App, History) ->
    run_app(AppName, App, intro, History);
survey_app(AppName, [Q | Qs] = Qlist, App, History) ->
    Qid = Q#question.id,
    Msg = Q#question.msg,
    Opts = Q#question.opts,
    Anchor = Q#question.anchor,
    io:format("~p > ~s~n", [AppName, Msg]),
    receive
        print_state ->
            io:format("~p is at ~p~n", [AppName, Qid]);
        print_history ->
            io:format("~p~n", [History]);
        InMsg ->
            case Opts of
                [] ->
                    survey_app(AppName, Qs, App, update_history({Qid, InMsg}, History));
                Opts ->
                    case lists:member(InMsg, Opts) of
                        true ->
                            AnchorQs = anchor_qs([{Qid, InMsg} | Anchor], App),
                            survey_app(AppName,
                                       AnchorQs ++ Qs,
                                       App,
                                       update_history({Qid, InMsg}, History));
                        false ->
                            survey_app(AppName, Qlist, App, History)
                    end
            end
    end.

anchor_qs(Anchor, App) ->
    [Q || Q <- App, Q#question.anchor =:= Anchor].

update_history({Qid, _Ans} = H, History) ->
    lists:keystore(Qid, 1, History, H).

run_app(survey_app = AppName, App, StateId, History) ->
    Q = lists:keyfind(StateId, #question.id, App),
    Qs = anchor_qs(Q#question.anchor, App),
    survey_app(AppName, Qs, App, History);
run_app(AppName, App, StateId, History) ->
    State = proplists:get_value(StateId, App),
    OutMsg = State#app_state.msg,
    io:format("~p > ~s~n", [AppName, OutMsg]),
    receive
        print_state ->
            io:format("~p is at ~p~n", [AppName, StateId]);
        print_history ->
            io:format("~p~n", [History]);
        {get_state_for_save, Pid} ->
            Pid ! {state_for_save, StateId, History},
            run_app(AppName, App, StateId, History);
        InMsg ->
            Logic = State#app_state.logic,
            NextStateId = Logic(InMsg),
            run_app(AppName, App, NextStateId, update_history({StateId, InMsg}, History))
    end.

launch_app(AppName, InitStateId) ->
    Pid = spawn(messaging, run_app,
                [AppName,
                 proplists:get_value(AppName, messaging:apps()),
                 InitStateId,
                 []]),
    register(AppName, Pid),
    ok.

interact(AppName, Msg) ->
    AppName ! Msg,
    ok.

show_state(AppName) ->
    case whereis(AppName) of
        undefined -> io:format("Application ~p is not running~n", [AppName]);
        _Pid -> AppName ! print_state
    end,
    ok.

show_history(AppName) ->
    case whereis(AppName) of
        undefined -> io:format("Application ~p is not running~n", [AppName]);
        _Pid -> 
            AppName ! print_history,
            ok
    end.

% Save app state to disk
save_state(AppName) ->
    case whereis(AppName) of
        undefined -> 
            {error, app_not_running};
        Pid ->
            % Create a message to get the current state and history
            Pid ! {get_state_for_save, self()},
            receive
                {state_for_save, StateId, History} ->
                    Filename = atom_to_list(AppName) ++ "_state.dat",
                    file:write_file(Filename, term_to_binary({StateId, History})),
                    ok
            after 
                5000 -> 
                    {error, timeout}
            end
    end.

% Load saved state from disk
load_state(AppName) ->
    Filename = atom_to_list(AppName) ++ "_state.dat",
    case file:read_file(Filename) of
        {ok, Binary} ->
            {StateId, History} = binary_to_term(Binary),
            {ok, StateId, History};
        {error, Reason} ->
            {error, Reason}
    end.

% Launch app with previously saved history
launch_app_with_history(AppName, InitStateId) ->
    case load_state(AppName) of
        {ok, StateId, History} ->
            io:format("Restoring ~p from saved state at ~p with ~p history entries~n", 
                     [AppName, StateId, length(History)]),
            Pid = spawn(messaging, run_app,
                       [AppName,
                        proplists:get_value(AppName, messaging:apps()),
                        StateId,
                        History]),
            register(AppName, Pid),
            ok;
        {error, _Reason} ->
            % If there's an error loading state, just start fresh
            io:format("No saved state found for ~p, starting fresh~n", [AppName]),
            launch_app(AppName, InitStateId)
    end.

% Question versioning functions
% Record initial version of all questions in an app
initialize_question_versions(AppName, Author) ->
    % Initialize security if not already done
    init_security(),
    
    % Get the app definition
    App = proplists:get_value(AppName, apps()),
    
    % For each state in the app, record its initial version
    lists:foreach(
        fun({StateId, State}) ->
            case is_record(State, app_state) of
                true ->
                    % For app_state records
                    Content = State#app_state.msg,
                    store_question_version(AppName, StateId, 1, Content, Author);
                false ->
                    % For question records
                    case is_record(State, question) of
                        true ->
                            Content = State#question.msg,
                            store_question_version(AppName, StateId, 1, Content, Author);
                        false ->
                            % Skip anything that's not a question or app_state
                            ok
                    end
            end
        end, App),
    ok.

% Store a new version of a question
store_question_version(AppName, QuestionId, Version, Content, Author) ->
    % Initialize security if not already done
    init_security(),
    
    % Create metadata record
    Metadata = #question_metadata{
        app_name = AppName,
        question_id = QuestionId,
        version = Version,
        timestamp = os:system_time(seconds),
        content = Content,
        author = Author
    },
    
    % Store in question history table
    ets:insert(?QUESTION_HISTORY_TABLE, {{AppName, QuestionId, Version}, Metadata}),
    ok.

% Get all versions of a question
get_question_versions(AppName, QuestionId) ->
    % Initialize security if not already done
    init_security(),
    
    % Query all versions for this question
    Versions = ets:match_object(?QUESTION_HISTORY_TABLE, {{'_', '_', '_'}, #question_metadata{app_name = AppName, question_id = QuestionId, _ = '_'}}),
    
    % Sort by version number
    SortedVersions = lists:sort(
        fun({_, #question_metadata{version = V1}}, {_, #question_metadata{version = V2}}) ->
            V1 =< V2
        end, Versions),
    
    % Return the metadata records
    [Metadata || {_, Metadata} <- SortedVersions].

% Get a specific version of a question
get_question_version(AppName, QuestionId, Version) ->
    % Initialize security if not already done
    init_security(),
    
    % Query specific version
    case ets:lookup(?QUESTION_HISTORY_TABLE, {AppName, QuestionId, Version}) of
        [{_, Metadata}] -> {ok, Metadata};
        [] -> {error, version_not_found}
    end.

% Update a question with a new version
update_question(AppName, QuestionId, NewContent, Author) ->
    % Get the current app
    App = proplists:get_value(AppName, apps()),
    
    % Find the question
    case find_question(App, QuestionId) of
        {ok, State, IsAppState} ->
            % Get the latest version number
            LatestVersion = get_latest_version(AppName, QuestionId),
            
            % Store the new version with incremented version number
            store_question_version(AppName, QuestionId, LatestVersion + 1, NewContent, Author),
            
            % Note: This doesn't actually modify the app in memory
            % In a real system, we would need to update the app and reload it
            {ok, LatestVersion + 1};
        {error, Reason} ->
            {error, Reason}
    end.

% Find a question in an app
find_question(App, QuestionId) ->
    case proplists:get_value(QuestionId, App) of
        undefined -> {error, question_not_found};
        State when is_record(State, app_state) -> {ok, State, true};
        State when is_record(State, question) -> {ok, State, false};
        _ -> {error, invalid_state_type}
    end.

% Get the latest version number for a question
get_latest_version(AppName, QuestionId) ->
    Versions = get_question_versions(AppName, QuestionId),
    case Versions of
        [] -> 0;
        _ ->
            LastVersion = lists:last(Versions),
            LastVersion#question_metadata.version
    end.
