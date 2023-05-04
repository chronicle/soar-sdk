import logging, time, uuid 
logger = logging.getLogger('simple_example')

class Base:
	def __init__(self, identifier, creation_time=None, modification_time=None, additional_properties = None):
		logger.info("Creating Base model object")
		if (not identifier):
			logger.error("Missing mandatory field: Identifier")
			raise SiemplifyArgumentsException("Identifier is required")
			
		self.identifier = identifier
		self.creation_time = creation_time
		self.modification_time = modification_time
		self.additional_properties = additional_properties
		logger.info("Base model created successfully")

class Insight(object):
	def __init__(self, case_id, creator, description, type, target_type, alert_identifier_scope, object_identifier, is_important, is_created_automatic, is_dismissed):
		self.case_id = case_id
		self.creator = creator
		self.description = description
		self.type = type
		self.target_type = target_type
		self.alert_identifier_scope = alert_identifier_scope
		self.object_identifier = object_identifier
		self.is_important = is_important
		self.is_created_automatic = is_created_automatic
		self.is_dismissed = is_dismissed

		class ContextStringItem(object):
	def __init__(self, name, value):
		self.name = name
		self.value = value

class ContextGroup(object):
	def __init__(self, is_highlight, group_name, items):
		self.is_highlight = is_highlight
		self.group_name = group_name
		self.items = []
		for item in items:
			self.items.append(ContextStringItem(**item))

class Tags(object):
	def __init__(self, case_id, tag, priority):
		self.case_id = case_id
		self.tag = tag
		self.priority = priority

class Value(object):
	def __init__(self, value, count, percentage):
		self.value = value
		self.count = count
		self.percentage = percentage
		
class SummaryField(object):
	def __init__(self, field_name, values):
		self.field_name = field_name
		self.values = []
		for value in values:
			self.values.append(Value(**value))

class Summary(object):
	def __init__(self, fields):
		self.fields = []
		for field in fields:
			self.fields.append(SummaryField(**field))
class Attachment(Base):
	def __init__(self, case_identifier, base64_blob,  type, name, description,is_favorite, orig_size, size):
		logger.info("Creating AlertInfo model object")
		self.case_identifier = case_identifier
		self.base64_blob = base64_blob
		self.type = type
		self.name = name
		self.description = description
		self.is_important = is_favorite
		self.orig_size = orig_size
		self.size = size
		logger.info("Attachment model created successfully")
	
	@staticmethod
	def fromfile(path, description = None, is_favorite = False):
		path = path.replace('\\', '/')
		if not os.path.isfile(path):
			raise IOError("File not found")
		name, type = os.path.splitext(os.path.split(path)[1])
		with open(path, "rb") as in_file:
			content = in_file.read()
			base64_blob = base64.b64encode(content)

		return Attachment(None, base64_blob, type, name, description, is_favorite,len(content), len(base64_blob))
