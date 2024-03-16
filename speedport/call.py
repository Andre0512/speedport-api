from datetime import datetime


class Call:
    def __init__(self, data, call_type):
        self._data = data
        self._call_type = call_type

    def __str__(self):
        return self.number

    def __repr__(self):
        return f"{self.__class__} ({self.__dict__})"

    def __getitem__(self, item):
        try:
            return self.__getattribute__(item)
        except AttributeError:
            return self._data.get(
                f"{self._call_type}_{item}", self.__getattribute__(item)
            )

    @property
    def data(self):
        return self._data

    @property
    def type(self):
        return self._call_type.replace("calls", "")

    @property
    def connection(self):
        return self._data.get(f"{self._call_type}_as")

    @property
    def duration(self):
        return int(self._data.get(f"{self._call_type}_duration", 0))

    @property
    def date(self):
        date = f'{self._data.get(f"{self._call_type}_date")} {self._data.get(f"{self._call_type}_time")}'
        return datetime.strptime(date, "%d.%m.%y %H:%M:%S")

    @property
    def number(self):
        return self._data.get(f"{self._call_type}_who")
