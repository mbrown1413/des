
import socket
from select import select
from collections import defaultdict
from multiprocessing import AuthenticationError
from multiprocessing.connection import Listener, Client

class WorkManager(object):

    def __init__(self, address, port, authkey=None):

        self.next_worker_id = 0
        self.tasks_finished = 0
        self.all_tasks_enumerated = False
        self.worker_ids = {}  # Maps connection objects to worker ids
        self.task_iter = iter(self.tasks())
        self.assigned_tasks = defaultdict(lambda: [])  # Maps connection objects to a list of assigned tasks
        self.dropped_tasks = []  # Dropped by workers on disconnect

        self.listener = Listener((address, port), authkey=authkey)
        self.listener._listener._socket.settimeout(0.0001)  # Set Nonblocking

    def run(self):

        try:
            while True:

                self.accept_new_clients()
                self.assign_tasks()

                # Exit Condition
                if self.all_tasks_enumerated and \
                        not self.worker_ids and \
                        not self.dropped_tasks:
                    break

        finally:
            self.finish()
            self.listener.close()

    def accept_new_clients(self):

        try:
            connection = self.listener.accept()
        except (AuthenticationError, EOFError) as e:
            self.log("Client failed to connect:", repr(e))
            connection = None
        except socket.timeout:
            connection = None
        if connection:

            # Send worker identifier
            worker_id = self.new_worker_id(connection)
            self.worker_ids[connection] = worker_id
            connection.send(worker_id)
            self.log("Connected", worker=worker_id)

            # Send two tasks initially.  This way there will always be a task
            # waiting on the worker's side of the connection.
            self.assign_task(connection)
            self.assign_task(connection)

    def assign_tasks(self):

        connections_to_remove = []
        for connection in select(self.worker_ids.keys(), [], [], 0.1)[0]:

                # Process results
                result = False
                try:
                    result = connection.recv()
                except (EOFError, IOError):
                    connections_to_remove.append(connection)
                    continue
                self.tasks_finished += 1
                self.assigned_tasks[connection].remove(result[0])

                # Assign task
                self.assign_task(connection)
                self.process_result(self.worker_ids[connection], result[0], result[1])

        for connection in connections_to_remove:
            self.remove_worker(connection)

    def get_task(self):

        # Check dropped_tasks
        if self.dropped_tasks:
            task = self.dropped_tasks.pop(0)
            return task

        # Grab task from task iterator
        try:
            return self.task_iter.next()
        except StopIteration:
            self.all_tasks_enumerated = True
            return False

    def assign_task(self, connection):
        task = self.get_task()
        if task is not False:
            self.assigned_tasks[connection].append(task)
        try:
            connection.send(task)
        except IOError:
            self.remove_worker(connection)
            return

    def remove_worker(self, connection):

        worker_id = self.worker_ids[connection]
        self.dropped_tasks.extend(self.assigned_tasks[connection])
        del self.worker_ids[connection]
        del self.assigned_tasks[connection]
        self.log("Disconnected", worker=worker_id)

    def new_worker_id(self, connection):
        worker_id = self.next_worker_id
        self.next_worker_id += 1
        return worker_id

    def tasks(self):
        raise NotImplementedError("A subclass must implement this.")

    def process_result(self, worker_id, task_data, result):
        raise NotImplementedError("A subclass must implement this.")

    def finish(self):
        pass

    def log(self, *items, **kwargs):
        worker = kwargs.pop("worker", None)
        if kwargs:
            raise ValueError("Unexpected kwargs: %s" % kwargs)
        if worker is None:
            identifier = "Manager"
        else:
            identifier = "Worker %s" % worker
        print "== %s ==" % identifier,
        for item in items:
            print item,
        print


class Worker(object):

    def __init__(self, address, port, authkey=None):

        self.connection = Client((address, port), authkey=authkey)
        self.worker_id = self.connection.recv()

    def run(self):
        while True:

            task_data = self.connection.recv()
            if task_data is False:
                return

            result = self.do_task(task_data)
            self.connection.send((task_data, result))

    def log(self, *items):
        print "== Worker %s ==" % self.worker_id,
        for item in items:
            print item,
        print

    def do_task(self, data):
        raise NotImplementedError("A subclass must implement this.")
