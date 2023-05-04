class BaseWallActivity(object):
	def __init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms):
		self.creator_user_id = creator_user_id
		self.id = id
		self.type = type
		self.case_id = case_id
		self.is_favorite = is_favorite
		self.modification_time_unix_time_in_ms = modification_time_unix_time_in_ms

class CaseCommentWallActivity(BaseWallActivity):
	def __init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms, comment):
		BaseWallActivity.__init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms)
		self.comment = comment

class CaseEvidenceWallActivity(BaseWallActivity):
	def __init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms, evidence_name, description, evidence_thumbnail_base64, evidence_id, file_type):
		BaseWallActivity.__init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms)
		self.evidence_name = evidence_name
		self.description = description
		self.evidence_thumbnail_base64 = evidence_thumbnail_base64
		self.evidence_id = evidence_id
		self.file_type = file_type
class CaseStatusChangedWallActivity(BaseWallActivity):
	def __init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms, description, activity_kind):
		BaseWallActivity.__init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms)
		self.activity_kind = activity_kind
		self.description = description

class CaseTaskChangedWallActivity(BaseWallActivity):
	def __init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms, status, priority, name, owner, completion_comment, completion_date_time, due_date):
		BaseWallActivity.__init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms)
		self.status = status
		self.name = name
		self.priority = priority
		self.owner = owner
		self.completion_comment = completion_comment
		self.completion_date_time = completion_date_time
		self.due_date = due_date

class CaseActionWallActivity(BaseWallActivity):
	def __init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms, action_trigger_type, integration, executing_user, playbook_name, status, action_provider, action_identifier, action_result):
		BaseWallActivity.__init__(self, creator_user_id, id, type, case_id, is_favorite, modification_time_unix_time_in_ms)
		self.action_trigger_type =action_trigger_type
		self.integration = integration
		self.executing_user = executing_user
		self.playbook_name = playbook_name
		self.status = status
		self.action_provider = action_provider
		self.action_identifier = action_identifier
		self.action_result = action_result

class CaseWallData(object):
	def __init__(self, case_action_wall_activities, case_comment_wall_activities, case_evidence_walla_ctivities, case_status_changed_wall_activities, case_task_changed_wall_activities):
		self.case_action_wall_activities = []
		self.case_comment_wall_activities = []
		self.case_evidence_walla_ctivities = []
		self.case_status_changed_wall_activities = []
		self.case_task_changed_wall_activities = []
		for case_action_wall_activitie in case_action_wall_activities:
			self.case_action_wall_activities.append(CaseActionWallActivity(**case_action_wall_activitie))
		for case_comment_wall_activitie in case_comment_wall_activities:
			self.case_comment_wall_activities.append(CaseCommentWallActivity(**case_comment_wall_activitie))
		for case_evidence_walla_ctivitie in case_evidence_walla_ctivities:
			self.case_evidence_walla_ctivities.append(CaseEvidenceWallActivity(**case_evidence_walla_ctivitie))
		for case_status_changed_wall_activitie in case_status_changed_wall_activities:
			self.case_status_changed_wall_activities.append(CaseStatusChangedWallActivity(**case_status_changed_wall_activitie))
		for case_task_changed_wall_activitie in case_task_changed_wall_activities:
			self.case_task_changed_wall_activities.append(CaseTaskChangedWallActivity(**case_task_changed_wall_activitie))