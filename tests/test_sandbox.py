from app.services.sandbox import run_cmd


def test_run_cmd_rejects_bad_argv():
    try:
        run_cmd([], timeout=1)
        assert False, "should have raised"
    except ValueError:
        pass
    try:
        run_cmd(["python", ""], timeout=1)
        assert False, "should have raised"
    except ValueError:
        pass


def test_run_cmd_timeout_and_output():
    result = run_cmd(["python3", "-c", "print('hello-sandbox')"], timeout=10)
    assert result.returncode == 0
    assert "hello-sandbox" in result.stdout
    assert result.timed_out is False


def test_run_cmd_not_found():
    result = run_cmd(["definitely-not-a-binary-xyz"], timeout=5)
    assert result.not_found is True
    assert result.returncode == 127


def test_never_uses_shell_metacharacters_as_command():
    # user-controlled string must not be interpreted by a shell
    result = run_cmd(["python3", "-c", "print('a; rm -rf /')"], timeout=10)
    assert result.returncode == 0
    assert "a; rm -rf /" in result.stdout
