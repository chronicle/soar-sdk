# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations


class BaseWallActivity:
    def __init__(
        self,
        creator_user_id: str,
        id: str,
        type: str,
        case_id: str,
        is_favorite: bool,
        modification_time_unix_time_in_ms: int,
    ) -> None:
        self.creator_user_id = creator_user_id
        self.id = id
        self.type = type
        self.case_id = case_id
        self.is_favorite = is_favorite
        self.modification_time_unix_time_in_ms = modification_time_unix_time_in_ms


class CaseCommentWallActivity(BaseWallActivity):
    def __init__(
        self,
        creator_user_id: str,
        id: str,
        type: str,
        case_id: str,
        is_favorite: bool,
        modification_time_unix_time_in_ms: int,
        comment: str,
    ) -> None:
        BaseWallActivity.__init__(
            self,
            creator_user_id,
            id,
            type,
            case_id,
            is_favorite,
            modification_time_unix_time_in_ms,
        )
        self.comment = comment


class CaseEvidenceWallActivity(BaseWallActivity):
    def __init__(
        self,
        creator_user_id: str,
        id: str,
        type: str,
        case_id: str,
        is_favorite: bool,
        modification_time_unix_time_in_ms: int,
        evidence_name: str,
        description: str,
        evidence_thumbnail_base64: str,
        evidence_id: str,
        file_type: str,
    ) -> None:
        BaseWallActivity.__init__(
            self,
            creator_user_id,
            id,
            type,
            case_id,
            is_favorite,
            modification_time_unix_time_in_ms,
        )
        self.evidence_name = evidence_name
        self.description = description
        self.evidence_thumbnail_base64 = evidence_thumbnail_base64
        self.evidence_id = evidence_id
        self.file_type = file_type


class CaseStatusChangedWallActivity(BaseWallActivity):
    def __init__(
        self,
        creator_user_id: str,
        id: str,
        type: str,
        case_id: str,
        is_favorite: bool,
        modification_time_unix_time_in_ms: int,
        description: str,
        activity_kind: str,
    ) -> None:
        BaseWallActivity.__init__(
            self,
            creator_user_id,
            id,
            type,
            case_id,
            is_favorite,
            modification_time_unix_time_in_ms,
        )
        self.activity_kind = activity_kind
        self.description = description


class CaseTaskChangedWallActivity(BaseWallActivity):
    def __init__(
        self,
        creator_user_id: str,
        id: str,
        type: str,
        case_id: str,
        is_favorite: bool,
        modification_time_unix_time_in_ms: int,
        status: str,
        priority: int,
        name: str,
        owner: str,
        completion_comment: str | None,
        completion_date_time: str | None,
        due_date: str | None,
    ) -> None:
        BaseWallActivity.__init__(
            self,
            creator_user_id,
            id,
            type,
            case_id,
            is_favorite,
            modification_time_unix_time_in_ms,
        )
        self.status = status
        self.name = name
        self.priority = priority
        self.owner = owner
        self.completion_comment = completion_comment
        self.completion_date_time = completion_date_time
        self.due_date = due_date


class CaseActionWallActivity(BaseWallActivity):
    def __init__(
        self,
        creator_user_id: str,
        id: str,
        type: str,
        case_id: str,
        is_favorite: bool,
        modification_time_unix_time_in_ms: int,
        action_trigger_type: str,
        integration: str,
        executing_user: str,
        playbook_name: str,
        status: str,
        action_provider: str,
        action_identifier: str,
        action_result: str,
    ) -> None:
        BaseWallActivity.__init__(
            self,
            creator_user_id,
            id,
            type,
            case_id,
            is_favorite,
            modification_time_unix_time_in_ms,
        )
        self.action_trigger_type = action_trigger_type
        self.integration = integration
        self.executing_user = executing_user
        self.playbook_name = playbook_name
        self.status = status
        self.action_provider = action_provider
        self.action_identifier = action_identifier
        self.action_result = action_result


class CaseWallData:
    def __init__(
        self,
        case_action_wall_activities: list[dict],
        case_comment_wall_activities: list[dict],
        case_evidence_walla_ctivities: list[dict],
        case_status_changed_wall_activities: list[dict],
        case_task_changed_wall_activities: list[dict],
    ) -> None:
        self.case_action_wall_activities: list[CaseActionWallActivity] = []
        self.case_comment_wall_activities: list[CaseCommentWallActivity] = []
        self.case_evidence_walla_ctivities: list[CaseEvidenceWallActivity] = []
        self.case_status_changed_wall_activities: list[
            CaseStatusChangedWallActivity
        ] = []
        self.case_task_changed_wall_activities: list[CaseTaskChangedWallActivity] = []
        for case_action_wall_activitie in case_action_wall_activities:
            self.case_action_wall_activities.append(
                CaseActionWallActivity(**case_action_wall_activitie),
            )
        for case_comment_wall_activitie in case_comment_wall_activities:
            self.case_comment_wall_activities.append(
                CaseCommentWallActivity(**case_comment_wall_activitie),
            )
        for case_evidence_walla_ctivitie in case_evidence_walla_ctivities:
            self.case_evidence_walla_ctivities.append(
                CaseEvidenceWallActivity(**case_evidence_walla_ctivitie),
            )
        for case_status_changed_wall_activitie in case_status_changed_wall_activities:
            self.case_status_changed_wall_activities.append(
                CaseStatusChangedWallActivity(**case_status_changed_wall_activitie),
            )
        for case_task_changed_wall_activitie in case_task_changed_wall_activities:
            self.case_task_changed_wall_activities.append(
                CaseTaskChangedWallActivity(**case_task_changed_wall_activitie),
            )
