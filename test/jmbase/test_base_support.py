#! /usr/bin/env python
import pytest
import copy
from jmbase import random_insert

def test_color_coded_logging():
    # TODO
    pass

@pytest.mark.parametrize('list1, list2', [
    [[1,2,3],[4,5,6]],
    [["a", "b", "c", "d", "e", "f", "g"], [1,2]],
])
def test_random_insert(list1, list2):
    l1 = len(list1)
    l2 = len(list2)
    # make a copy of the old version so we can
    # check ordering:
    old_list1 = copy.deepcopy(list1)
    random_insert(list1, list2)
    assert len(list1) == l1+l2
    assert all([x in list1 for x in list2])
    assert all([x in list1 for x in old_list1])
    # check the order of every element in the original
    # list is preserved:
    for x, y in [(old_list1[i], old_list1[i+1]) for i in range(
        len(old_list1)-1)]:
        # no need to catch ValueError, it should never throw
        # so that's a fail anyway.
        i_x = list1.index(x)
        i_y = list1.index(y)
        assert i_y > i_x
