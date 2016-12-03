import sys, os
from jmclient import rand_exp_array, rand_norm_array, rand_pow_array
try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print 'Install matplotlib and numpy to run this test'
    sys.exit(0)


def test_power():
    a = 5.  # shape
    samples = 10000
    s1 = np.random.power(a, samples)
    s2 = common.rand_pow_array(a, samples)

    plt.figure('power test')
    count1, bins1, ignored1 = plt.hist(s1,
                                       bins=30,
                                       label='numpy',
                                       histtype='step')
    x = np.linspace(0, 1, 100)
    y = a * x**(a - 1.0)
    normed_y1 = samples * np.diff(bins1)[0] * y
    plt.plot(x, normed_y1, label='numpy.random.power fit')

    count2, bins2, ignored2 = plt.hist(s2,
                                       bins=30,
                                       label='joinmarket',
                                       histtype='step')
    normed_y2 = samples * np.diff(bins2)[0] * y
    plt.plot(x, normed_y2, label='common.rand_pow_array fit')
    plt.title('testing power distribution')
    plt.legend(loc='upper left')
    plt.show()


def test_choice():

    xaxis_divisions = 100
    sinp = np.sin(np.arange(xaxis_divisions) * 2 * np.pi / xaxis_divisions)**2
    sinp /= sum(sinp)
    sinp = list(sinp)

    sincp = np.sinc((np.arange(xaxis_divisions) - 2 * xaxis_divisions / 3) * 2 *
                    np.pi / xaxis_divisions)**2
    sincp /= sum(sincp)
    sincp = list(sincp)

    x = np.arange(xaxis_divisions) * 2 * np.pi / xaxis_divisions
    gamma2p = x**2 * np.exp(-2 * x)
    gamma2p /= sum(gamma2p)
    gamma2p = list(gamma2p)

    plt.figure('choice test')
    for p, name in ((sinp, 'sin'), (sincp, 'sinc'), (gamma2p, 'gamma(2, 2)')):
        #for p, name in ((sincp, 'sincp'), ):
        samples = 50000
        common_data = []
        numpy_data = []
        for i in range(samples):
            cpoint = common.rand_weighted_choice(xaxis_divisions, p)
            common_data.append(cpoint)
            nppoint = np.random.choice(xaxis_divisions, p=p)
            numpy_data.append(nppoint)

        count1, bins1, ignored1 = plt.hist(common_data,
                                           bins=xaxis_divisions,
                                           label=name + 'joinmarket',
                                           histtype='step')
        count2, bins2, ignored2 = plt.hist(numpy_data,
                                           bins=xaxis_divisions,
                                           label=name + 'numpy',
                                           histtype='step')

    plt.title('testing choice')
    plt.legend(loc='upper left')
    plt.show()


def main():
    test_power()
    test_choice()


if __name__ == '__main__':
    main()
