
import socket
from select import select
from collections import defaultdict
from multiprocessing import AuthenticationError
from multiprocessing.connection import Listener, Client

class WorkManager(object):

    def __init__(self, address, port, authkey=None):

        self.tasks_finished = 0
        self.done = False
        self.worker_connections = []
        self.task_iter = iter(self.tasks())
        self.assigned_tasks = defaultdict(lambda: [])  # Maps connection objects to a list of assigned tasks
        self.dropped_tasks = []  # Dropped by workers on disconnect

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
        except (AuthenticationError, EOFError) as e:
            print "Client failed to connect:", repr(e)
            connection = None
        except socket.timeout:
            connection = None
        if connection:
            # Send two tasks initially.  This way there will always be a task
            # waiting on the worker's side of the connection.
            self.assign_task(connection)
            self.assign_task(connection)
            self.worker_connections.append(connection)

    def assign_tasks(self):

        connections_to_remove = []
        for connection in select(self.worker_connections, [], [], 1)[0]:

                # Send new task and process the old results
                result = False
                try:
                    result = connection.recv()
                except (EOFError, IOError):
                    connections_to_remove.append(connection)
                    continue
                self.assign_task(connection)
                self.tasks_finished += 1
                self.assigned_tasks[connection].remove(result[0])
                self.process_result(result)

                if self.done:
                    connections_to_remove.append(connection)

        for connection in connections_to_remove:
            self.remove_worker(connection)

    def get_task(self):
        if self.dropped_tasks:
            task = self.dropped_tasks.pop(0)
            #print "Recovering Task:", task
            return task
        try:
            return self.task_iter.next()
        except StopIteration:
            self.done = True
            return False

    def assign_task(self, connection):
        task = self.get_task()
        self.assigned_tasks[connection].append(task)
        try:
            connection.send(task)
        except IOError:
            self.remove_worker(connection)
            return

    def remove_worker(self, connection):
        print "Worker", connection.fileno(), "disconnected"
        #print "Tasks dropped:", self.assigned_tasks[connection]
        self.dropped_tasks.extend(self.assigned_tasks[connection])
        self.worker_connections.remove(connection)
        del self.assigned_tasks[connection]

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
