INSERT INTO public.teachers (user_id) 
SELECT id FROM auth.users WHERE email = 'YOUR_TEACHER_EMAIL@school.ac.th';