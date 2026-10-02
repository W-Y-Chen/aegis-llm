"""冒烟测试：状态机、评估器、算子与攻击主循环。"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.evaluator import DefensePosture, HeuristicEvaluator  # noqa: E402
from aegis.operators import OPERATORS  # noqa: E402
from aegis.state import StateMachine  # noqa: E402


def test_state_machine_transit_and_backtrack():
    sm = StateMachine(goal_keywords=("步骤",), max_turns=4)
    s0 = sm.init()
    assert s0.turn == 0
    s1 = sm.transit("role_play", "p1", "r1", "weak_refusal", "[角色扮演]")
    assert s1.turn == 1
    sm.backtrack()
    assert sm.current.turn == 0


def test_goal_detection():
    sm = StateMachine(goal_keywords=("步骤", "首先"))
    assert sm.reached_goal("具体步骤：首先……")
    assert not sm.reached_goal("我无法协助")


def test_evaluator_five_levels():
    ev = HeuristicEvaluator()
    assert ev.assess("抱歉，我无法协助这个请求。") == DefensePosture.STRONG_REFUSAL
    assert ev.assess("步骤：首先准备环境，然后设定参数", ("步骤", "首先")) == DefensePosture.FULL_LEAK


def test_operators_build_prompt():
    sm = StateMachine(goal_keywords=("x",))
    state = sm.init()
    for op in OPERATORS.values():
        prompt = op.build(state, "测试目标")
        assert isinstance(prompt, str) and len(prompt) > 10
