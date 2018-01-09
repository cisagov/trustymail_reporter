#!/usr/bin/env python

import math
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib as mpl
from mpl_toolkits.basemap import Basemap
from matplotlib.patches import Rectangle, Ellipse, RegularPolygon
from matplotlib.collections import PatchCollection
from matplotlib.ticker import MaxNLocator
from matplotlib.dates import DateFormatter
from textwrap import TextWrapper
from pandas import DataFrame, Series
import pandas as pd
from itertools import chain

# Blue, Green, Yellow, Orange, Red,
BLUE =      '#5c90ba'
GREEN =     '#7bbe5e'
YELLOW =    '#cfc666'
ORANGE =    '#cf9c66'
RED =       '#c66270'
COLORS =      (BLUE, YELLOW, ORANGE, RED, GREEN) # vuln colors first, then green

DARK_BLUE =      '#3c698e'
DARK_GREEN =     '#56943c'
DARK_YELLOW =    '#b1a738'
DARK_ORANGE =    '#b17638'
DARK_RED =       '#a13a49'
COLORS_DARK = (DARK_BLUE, DARK_YELLOW, DARK_ORANGE, DARK_RED, DARK_GREEN)

LIGHT_BLUE =      '#92b5d1'
LIGHT_GREEN =     '#a8d494'
LIGHT_YELLOW =    '#e1dca0'
LIGHT_ORANGE =    '#e1c2a0'
LIGHT_RED =       '#e8c0c5'
COLORS_LIGHT = (LIGHT_BLUE, LIGHT_YELLOW, LIGHT_ORANGE, LIGHT_RED, LIGHT_GREEN)

GREY_LIGHT = '#e8e8e8'
GREY_MID = '#cecece'
GREY_DARK = '#a1a1a1'

PIE_COLORS = COLORS + COLORS_DARK + COLORS_LIGHT

TOO_SMALL_WEDGE = 30

#import IPython; IPython.embed() #<<<<<BREAKPOINT>>>>>>>


def setup():
    fig_width_pt = 505.89                     # Get this from LaTeX using \showthe\columnwidth (see *.width file)
    inches_per_pt = 1.0 / 72.27               # Convert pt to inch
    golden_mean = (np.sqrt(5)-1.0)/2.0        # Aesthetic ratio
    fig_width = fig_width_pt * inches_per_pt  # width in inches
    fig_height = fig_width * golden_mean      # height in inches
    fig_size = [fig_width, fig_height]
    params = {'backend': 'pdf',
              # 'font.family': 'sans-serif',
              # 'font.sans-serif': ['Avenir Next'],
              'axes.labelsize': 10,
              'font.size': 10,
              'legend.fontsize': 8,
              'xtick.labelsize': 8,
              'ytick.labelsize': 8,
              'font.size': 10,
              'text.usetex': False,
              'figure.figsize': fig_size}
    plt.rcParams.update(params)

def wrapLabels(labels, width):
    wrapper = TextWrapper(width=width, break_long_words=False)
    result = []
    for label in labels:
        result.append(wrapper.fill(label))
    return result

class MyMessage(object):
    def __init__(self, message):
        self.message = message

    def plot(self, filename, size=1.0):
        fig = plt.figure(1)
        fig.set_size_inches(fig.get_size_inches() * size)
        ax = fig.add_subplot(1,1,1)
        ax.xaxis.set_visible(False)
        ax.yaxis.set_visible(False)
        ax.spines['left'].set_visible(False)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.text(0.5, 0.5, self.message,
                horizontalalignment='center',
                verticalalignment='center',
                fontsize=20 * size, color=DARK_GREEN,
                transform=ax.transAxes)
        plt.savefig(filename + '.pdf')
        plt.close()

class MyDistributionBar(object):
    def __init__(self, series, yscale='linear', xlabel=None, ylabel=None, final_bucket_accumulate=False, x_major_tick_count=10, region_colors=[], x_limit_extra=0):
        self.series = series
        self.yscale = yscale
        self.xlabel = xlabel
        self.ylabel = ylabel
        self.final_bucket_accumulate = final_bucket_accumulate
        self.x_major_tick_count = x_major_tick_count
        self.region_colors = region_colors
        self.x_limit_extra = x_limit_extra      # Used to add a little extra space to the end of the x axis to make the final bucket more readable

    def plot(self, filename, size=1.0):
        fig = plt.figure(figsize=(9,2.75))
        fig.set_size_inches(fig.get_size_inches() * size)
        ax = fig.add_subplot(1,1,1)
        ax.set_yscale(self.yscale)
        pos = np.arange(len(self.series))       # the bar centers on the x axis
        # Manually set x-axis range to be between 0 and the highest value in the series plus any desired extra space (x_limit_extra)
        ax.set_xlim([0,self.series.index[-1] + self.x_limit_extra])

        if self.xlabel:
            plt.xlabel(self.xlabel)
        if self.ylabel:
            plt.ylabel(self.ylabel)

        tick_labels = list(self.series.index)
        if self.final_bucket_accumulate:
            tick_labels[-1] = '{}+'.format(tick_labels[-1])

        plt.bar(pos, self.series.values, tick_label=tick_labels, align='center', color='#000000', edgecolor='#000000')
        y_max = ax.get_ylim()[1]

        # Colorize regions and add dividing lines if region_colors present
        previous_day = 0
        for (day,bgcolor) in self.region_colors:
            plt.axvline(x=day, color='#777777', linewidth=0.5)   # draw reference lines
            ax.annotate('{} Days '.format(day), xy=(day-1,y_max), rotation='vertical', fontsize=10, color='#666666', ha='right', va='top')
            ax.add_patch(Rectangle((previous_day,0), day-previous_day, y_max, facecolor=bgcolor, alpha=0.4, edgecolor=None, zorder=0))
            previous_day = day
        ax.add_patch(Rectangle((previous_day,0), (self.series.index[-1] - previous_day + self.x_limit_extra), y_max, facecolor='#000000', alpha=0.4, edgecolor=None, zorder=0))

        tick_interval = len(self.series) / (self.x_major_tick_count-1)
        for i,tick in enumerate(ax.xaxis.get_major_ticks()):
            if i % tick_interval:
                tick.set_visible(False)
            else:
                tick.set_visible(True)
                tick.set_label('{}'.format(self.series.index[i]))

        if self.final_bucket_accumulate:
            tick.set_visible(True)      # Show final tick (just in case it isn't already visible)

        ax.tick_params(direction='out') # put ticks on the outside of the axes
        ax.yaxis.grid(True)
        ax.yaxis.tick_left() # ticks only on left
        ax.yaxis.set_visible(True)
        ax.xaxis.tick_bottom() # ticks only on bottom
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        fig.set_tight_layout(True)
        plt.savefig(filename + '.pdf')
        plt.close()

class MyStackedLine(object):
    def __init__(self, data_frame, yscale='linear', xlabel=None, ylabel=None, data_labels=None, data_fill_colors=None):
        self.df = data_frame
        self.yscale = yscale
        self.xlabel = xlabel
        self.ylabel = ylabel
        self.data_labels = data_labels
        self.data_fill_colors = data_fill_colors

    def plot(self, filename, size=1.0):
        df = self.df
        fig, axes = plt.subplots(figsize=(9,2.75))
        fig.set_size_inches(fig.get_size_inches() * size)
        axes.stackplot(df.index, df['young'].values.astype(np.int), df['old'].values.astype(np.int), labels=self.data_labels, colors=self.data_fill_colors, alpha=0.2)
        # axes.locator_params(axis='x', nbins=8, tight=True)       # Limit x-axis to 8 ticks; doesn't seem to work with Date data :(
        axes.yaxis.tick_left() # ticks only on left
        axes.yaxis.grid(True)
        axes.xaxis.tick_bottom() # ticks only on bottom
        axes.xaxis.set_major_formatter(DateFormatter('%Y-%m-%d'))
        axes.set_axisbelow(True)
        axes.spines['top'].set_visible(False)
        axes.spines['right'].set_visible(False)
        if self.xlabel:
            plt.xlabel(self.xlabel)
        if self.ylabel:
            plt.ylabel(self.ylabel)
        leg = plt.legend(fancybox=True, loc='lower center', ncol=2, prop={'size':9}, bbox_to_anchor=(0.5, 0.99))
        leg.get_frame().set_alpha(0.5)  # set the alpha value of the legend: it will be translucent
        # for i,tick in enumerate(axes.xaxis.get_major_ticks()):
        #     tick.label.set_fontsize(6)        # If we want a smaller font size for the date tick labels
        fig.set_tight_layout(True)
        plt.savefig(filename + '.pdf')
        plt.close()

class MyDonutPie(object):
    def __init__(self, percentage_full, label, fill_color):
        self.percentage_full = percentage_full
        self.label = label
        self.fill_color = fill_color

    def plot(self, filename, size=1.0):
        # Override default figsize (make square), then scale by size parameter
        fig_width = fig_height = 4.0 * size
        plt.rcParams.update({'figure.figsize':[fig_width, fig_height]})
        extent = mpl.transforms.Bbox(((0, 0), (fig_width, fig_height)))  # Minimize whitespace around chart

        labels = '', ''
        sizes = [100 - self.percentage_full, self.percentage_full]
        colors = ['white', self.fill_color]

        # Set edge color to black
        # See https://matplotlib.org/users/dflt_style_changes.html#patch-edges-and-color
        plt.rcParams['patch.force_edgecolor'] = True
        plt.rcParams['patch.facecolor'] = 'b'

        plt.pie(sizes, labels=labels, colors=colors, shadow=False, startangle=90) #autopct='%1.1f%%'

        # Draw a circle at the center of pie to make it look like a donut
        centre_circle = plt.Circle((0,0),0.75,color='black', fc='white',linewidth=1.25)
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)

        plt.text(0, 0.15, str(self.percentage_full) + '%', horizontalalignment='center', verticalalignment='center', fontsize=50)
        plt.text(0, -0.2, self.label, horizontalalignment='center', verticalalignment='center', fontsize=19.5, fontweight='bold')
        plt.tight_layout(pad=0.0, w_pad=0.0, h_pad=0.0)

        # Set aspect ratio to be equal so that pie is drawn as a circle.
        plt.axis('equal')
        # plt.show()
        plt.savefig(filename + '.pdf', bbox_inches=extent, pad_inches=0)
        plt.close()

if __name__=="__main__":
    setup()

    m = MyMessage('Figure Omitted\nNo Vulnerabilities Detected')
    m.plot('message')
