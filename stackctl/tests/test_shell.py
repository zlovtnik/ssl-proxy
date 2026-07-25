"""Tests for stackctl subprocess wrappers (shell.py)."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from shell import ShellError, _run, helm, kubectl


class TestKubectl:
    """Test kubectl command construction and context propagation."""

    def test_basic_command(self):
        """kubectl with no context/kubeconfig builds plain command."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "get", "pods"],
                returncode=0,
                stdout="pod-1\npod-2\n",
                stderr="",
            )
            result = kubectl("get", "pods")
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args == ["kubectl", "get", "pods"]
            assert result.stdout == "pod-1\npod-2\n"

    def test_with_context(self):
        """kubectl --context flag is appended when context is set."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "--context", "prod", "get", "pods"],
                returncode=0,
                stdout="",
                stderr="",
            )
            kubectl("get", "pods", context="prod")
            args = mock_run.call_args[0][0]
            assert "--context" in args
            ctx_idx = args.index("--context")
            assert args[ctx_idx + 1] == "prod"

    def test_with_kubeconfig(self):
        """kubectl --kubeconfig flag is appended when kubeconfig is set."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "--kubeconfig", "/path/to/kubeconfig", "get", "pods"],
                returncode=0,
                stdout="",
                stderr="",
            )
            kubectl("get", "pods", kubeconfig="/path/to/kubeconfig")
            args = mock_run.call_args[0][0]
            assert "--kubeconfig" in args
            kc_idx = args.index("--kubeconfig")
            assert args[kc_idx + 1] == "/path/to/kubeconfig"

    def test_kubeconfig_takes_precedence_over_context(self):
        """When both kubeconfig and context are set, kubeconfig wins."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "--kubeconfig", "/path/to/kubeconfig", "get", "pods"],
                returncode=0,
                stdout="",
                stderr="",
            )
            kubectl("get", "pods", context="prod", kubeconfig="/path/to/kubeconfig")
            args = mock_run.call_args[0][0]
            assert "--kubeconfig" in args
            assert "--context" not in args

    def test_no_context_or_kubeconfig(self):
        """Neither --context nor --kubeconfig when both are None."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "get", "pods"],
                returncode=0,
                stdout="",
                stderr="",
            )
            kubectl("get", "pods", context=None, kubeconfig=None)
            args = mock_run.call_args[0][0]
            assert "--context" not in args
            assert "--kubeconfig" not in args

    def test_multiple_args_preserved(self):
        """All positional args are forwarded in order."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "get", "deploy", "-n", "default", "-o", "yaml"],
                returncode=0,
                stdout="",
                stderr="",
            )
            kubectl("get", "deploy", "-n", "default", "-o", "yaml")
            args = mock_run.call_args[0][0]
            assert args == ["kubectl", "get", "deploy", "-n", "default", "-o", "yaml"]

    def test_check_false_suppresses_exception(self):
        """check=False returns CompletedProcess even on non-zero exit."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "get", "nonexistent"],
                returncode=1,
                stdout="",
                stderr='Error from server: not found',
            )
            result = kubectl("get", "nonexistent", check=False)
            assert result.returncode == 1
            assert "not found" in result.stderr

    def test_check_true_raises_on_nonzero(self):
        """check=True raises ShellError on non-zero exit."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "get", "nonexistent"],
                returncode=1,
                stdout="",
                stderr='Error from server: not found',
            )
            with pytest.raises(ShellError) as exc_info:
                kubectl("get", "nonexistent")
            assert exc_info.value.returncode == 1
            assert "not found" in exc_info.value.stderr

    def test_input_text_passed_to_subprocess(self):
        """input_text is forwarded to subprocess.run."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "apply", "-f", "-"],
                returncode=0,
                stdout="created",
                stderr="",
            )
            kubectl("apply", "-f", "-", input_text="apiVersion: v1\nkind: Pod\n")
            assert mock_run.call_args[1]["input"] == "apiVersion: v1\nkind: Pod\n"


class TestHelm:
    """Test helm command construction and context propagation."""

    def test_basic_command(self):
        """helm with no context builds plain command."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["helm", "list"],
                returncode=0,
                stdout="NAME\tNAMESPACE\n",
                stderr="",
            )
            result = helm("list")
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args == ["helm", "list"]
            assert "NAME" in result.stdout

    def test_with_kubeconfig(self):
        """helm --kubeconfig flag is appended when kubeconfig is set."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["helm", "--kubeconfig", "/path/to/kubeconfig", "list"],
                returncode=0,
                stdout="",
                stderr="",
            )
            helm("list", kubeconfig="/path/to/kubeconfig")
            args = mock_run.call_args[0][0]
            assert "--kubeconfig" in args
            kc_idx = args.index("--kubeconfig")
            assert args[kc_idx + 1] == "/path/to/kubeconfig"

    def test_with_context(self):
        """helm --kube-context flag is appended when context is set."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["helm", "--kube-context", "prod", "list"],
                returncode=0,
                stdout="",
                stderr="",
            )
            helm("list", context="prod")
            args = mock_run.call_args[0][0]
            assert "--kube-context" in args
            ctx_idx = args.index("--kube-context")
            assert args[ctx_idx + 1] == "prod"

    def test_kubeconfig_takes_precedence_over_context(self):
        """When both kubeconfig and context are set, kubeconfig wins."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["helm", "--kubeconfig", "/path/to/kubeconfig", "list"],
                returncode=0,
                stdout="",
                stderr="",
            )
            helm("list", context="prod", kubeconfig="/path/to/kubeconfig")
            args = mock_run.call_args[0][0]
            assert "--kubeconfig" in args
            assert "--kube-context" not in args

    def test_stream_mode_uses_popen(self):
        """stream=True uses subprocess.Popen instead of subprocess.run."""
        with patch("shell.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = ["line1\n", "line2\n"]
            mock_proc.stderr = []
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            result = helm("list", stream=True)
            mock_popen.assert_called_once()
            args = mock_popen.call_args[0][0]
            assert args == ["helm", "list"]
            assert result.returncode == 0
            assert "line1" in result.stdout

    def test_stream_mode_nonzero_raises(self):
        """stream=True with non-zero exit raises ShellError."""
        with patch("shell.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = []
            mock_proc.stderr = ["error: something failed\n"]
            mock_proc.returncode = 1
            mock_popen.return_value = mock_proc

            with pytest.raises(ShellError) as exc_info:
                helm("list", stream=True)
            assert exc_info.value.returncode == 1

    def test_check_false_suppresses_exception(self):
        """check=False returns CompletedProcess even on non-zero exit."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["helm", "get", "nonexistent"],
                returncode=1,
                stdout="",
                stderr="Error: release not found",
            )
            result = helm("get", "nonexistent", check=False)
            assert result.returncode == 1

    def test_check_true_raises_on_nonzero(self):
        """check=True raises ShellError on non-zero exit."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["helm", "get", "nonexistent"],
                returncode=1,
                stdout="",
                stderr="Error: release not found",
            )
            with pytest.raises(ShellError) as exc_info:
                helm("get", "nonexistent")
            assert exc_info.value.returncode == 1
            assert "release not found" in exc_info.value.stderr


class TestShellError:
    """Test ShellError exception class."""

    def test_message_includes_returncode_and_stderr(self):
        err = ShellError(
            command=("kubectl", "get", "pods"),
            returncode=1,
            stdout="",
            stderr="Error from server: not found",
        )
        assert "rc=1" in str(err)
        assert "not found" in str(err)
        assert err.returncode == 1
        assert err.stderr == "Error from server: not found"

    def test_message_falls_back_to_stdout(self):
        err = ShellError(
            command=("helm", "list"),
            returncode=1,
            stdout="something went wrong",
            stderr="",
        )
        assert "something went wrong" in str(err)

    def test_message_with_empty_output(self):
        err = ShellError(
            command=("kubectl", "delete", "pod"),
            returncode=1,
            stdout="",
            stderr="",
        )
        assert "rc=1" in str(err)
        assert "kubectl delete pod" in str(err)

    def test_command_tuple_preserved(self):
        err = ShellError(
            command=("helm", "upgrade", "release", "./chart"),
            returncode=2,
            stdout="",
            stderr="timeout",
        )
        assert err.command == ("helm", "upgrade", "release", "./chart")


class TestRun:
    """Test the internal _run helper."""

    def test_capture_false_does_not_capture_output(self):
        """capture=False passes capture_output=False to subprocess.run."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["echo", "hello"],
                returncode=0,
                stdout="",
                stderr="",
            )
            _run(["echo", "hello"], capture=False)
            assert mock_run.call_args[1]["capture_output"] is False

    def test_capture_true_captures_output(self):
        """capture=True passes capture_output=True to subprocess.run."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["echo", "hello"],
                returncode=0,
                stdout="hello\n",
                stderr="",
            )
            result = _run(["echo", "hello"], capture=True)
            assert result.stdout == "hello\n"

    def test_input_text_passed_to_subprocess(self):
        """input_text is forwarded to subprocess.run as input."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["kubectl", "apply", "-f", "-"],
                returncode=0,
                stdout="created",
                stderr="",
            )
            _run(["kubectl", "apply", "-f", "-"], input_text="kind: Pod")
            assert mock_run.call_args[1]["input"] == "kind: Pod"

    def test_check_false_returns_on_nonzero(self):
        """check=False returns the CompletedProcess even on failure."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["false"],
                returncode=1,
                stdout="",
                stderr="",
            )
            result = _run(["false"], check=False)
            assert result.returncode == 1

    def test_check_true_raises_on_nonzero(self):
        """check=True raises ShellError on non-zero exit."""
        with patch("shell.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["false"],
                returncode=1,
                stdout="",
                stderr="command not found",
            )
            with pytest.raises(ShellError):
                _run(["false"], check=True)