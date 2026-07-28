-- The "user account created" notification also fires for service accounts, so
-- the copy branches on the created_account_type label. Messages enqueued before
-- this migration have no such label and render the user wording.
UPDATE notification_templates
SET
	title_template = E'{{ if eq .Labels.created_account_type "service" }}Service{{ else }}User{{ end }} account "{{.Labels.created_account_name}}" created',
	body_template = E'{{ $account := "user" }}{{ if eq .Labels.created_account_type "service" }}{{ $account = "service" }}{{ end }}' ||
					E'New {{ $account }} account **{{.Labels.created_account_name}}** has been created.\n\n' ||
					E'This new {{ $account }} account was created {{if .Labels.created_account_user_name}}for **{{.Labels.created_account_user_name}}** {{end}}by **{{.Labels.initiator}}**.'
WHERE
	id = '4e19c0ac-94e1-4532-9515-d1801aa283b2';
