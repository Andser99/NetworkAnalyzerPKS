from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.stacklayout import StackLayout
from kivy.uix.widget import Widget

import packet



class MainPage(Widget):
    stack_layout = StackLayout()
    grid_layout = GridLayout()

    def populate_list(self, frame_list: packet.Packet):
        for frame in frame_list:
            new_label = Label(text=frame.to_string(), font_size='20sp')
            self.stack_layout.add_widget(new_label)
        self.grid_layout.add_widget(self.stack_layout)
