def get_user_input(request, param, default=""):
    return request.args.get(param, default)


def get_post_data(request, field):
    return request.form.get(field, "")
