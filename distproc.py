
import socket
from select import select
from multiprocessing import AuthenticationError
from multiprocessing.connection import Listener, Client

class WorkManager(object):

    def __init__(self, address, port, authkey=None):

        self.tasks_finished = 0
        self.done = False
        self.worker_connections = []
        self.task_iter = iter(self.tasks())

        self.listener = Listener((address, port), authkey=authkey)
        self.listener._listener._socket.settimeout(0.0001)  # Set Nonblocking

    def run(self):

        try:

            while not self.done or self.worker_connections:

                if not self.done:
                    self.accept_new_clients()

                self.assign_tasks()

        except Exception:
            self.finish()
            self.listener.close()
            raise

    def accept_new_clients(self):

        try:
            connection = self.listener.accept()
        except AuthenticationError as e:
            print "Client failed to connect:", repr(e)
            connection = None
        except socket.timeout:
            connection = None
        if connection:
            # Send two tasks initially.  This way there will always be a task
            # waiting on the worker's side of the connection.
            connection.send(self.get_task())
            connection.send(self.get_task())
            self.worker_connections.append(connection)

    def assign_tasks(self):

        connections_to_remove = []
        for connection in select(self.worker_connections, [], [], 1)[0]:

                # Send new task and process the old results
                task = self.get_task()
                connection.send(task)
                result = connection.recv()
                self.tasks_finished += 1
                self.process_result(result)

                if task is False:
                    self.done = True
                    connections_to_remove.append(connection)

        for connection in connections_to_remove:
            self.worker_connections.remove(connection)

    def get_task(self):
        try:
            return self.task_iter.next()
        except StopIteration:
            return False

    def tasks(self):
        raise NotImplementedError("A subclass must implement this.")

    def process_result(self, result):
        raise NotImplementedError("A subclass must implement this.")

    def finish(self):
        pass

class Worker(object):

    def __init__(self, address, port, authkey=None):

        self.connection = Client((address, port), authkey=authkey)

    def run(self):
        while True:

            task_data = self.connection.recv()
            if task_data is False:
                return

            result = self.do_task(task_data)
            self.connection.send((task_data, result))

    def do_task(self, data):
        raise NotImplementedError("A subclass must implement this.")
