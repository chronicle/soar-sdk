import calendar

import locale
import SiemplifyUtils
from SiemplifyAction import *
import datetime


class PermittedTime:
    def __init__(self, parameters):
        self.start_time = self.get_time(parameters["Permitted Start Time(Example: 9:55:24)"])
        self.end_time = self.get_time(parameters["Permitted End Time(Example: 17:23:21)"])
        self.days = []
        if (parameters["Monday"].lower() == "true"):
            self.days.append(0)
        if (parameters["Tuesday"].lower() == "true"):
            self.days.append(1)
        if (parameters["Wednesday"].lower() == "true"):
            self.days.append(2)
        if (parameters["Thursday"].lower() == "true"):
            self.days.append(3)
        if (parameters["Friday"].lower() == "true"):
            self.days.append(4)
        if (parameters["Saturday"].lower() == "true"):
            self.days.append(5)
        if (parameters["Sunday"].lower() == "true"):
            self.days.append(6)

    def get_time(self, time_str):
        try:
            return datetime.datetime.strptime(time_str, "%H:%M:%S").time()
        except ValueError:
            return datetime.datetime.strptime(time_str, "%H:%M").time()

    def __repr__(self):
        return "between %s - %s on %s" % (
        self.start_time, self.end_time, map(lambda d: calendar.day_name[d], self.days))


from SiemplifyMock import SiemplifyMock

def main():
    siemplify = SiemplifyMock()

    permitted_time = PermittedTime(siemplify.parameters)
    if not siemplify.current_alert:
        siemplify.end("No alert selected", None)

    alert_start = siemplify.current_alert.start_time
    print alert_start
    alert_start_time = alert_start.time()
    is_permitted = (permitted_time.start_time >= alert_start_time and
                    alert_start_time <= permitted_time.end_time and
                    alert_start.weekday() in permitted_time.days)

    output_message = "%s Case Time of %s is %s within condition parameters of %s" % (
    siemplify.current_alert.start_time, alert_start.strftime("%A, %x %X"), "" if is_permitted else "not ",
    permitted_time)

    siemplify.end(output_message, str(is_permitted))


if __name__ == '__main__':
    main()