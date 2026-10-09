-- 1. สร้างโครงสร้างตาราง
CREATE TABLE public.teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);

CREATE TABLE public.students (
    id TEXT PRIMARY KEY,
    title TEXT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    section TEXT,
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT
);

CREATE TABLE public.attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    kind TEXT CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, kind)
);

CREATE TABLE public.progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    done BOOLEAN DEFAULT false,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, unit)
);

CREATE TABLE public.submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind TEXT CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER NULL,
    teacher_comment TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE public.materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind TEXT CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. ฟังก์ชันตรวจสอบสิทธิ์ผู้สอน (Security Definer)
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM public.teachers WHERE user_id = auth.uid());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- 3. เปิด RLS
ALTER TABLE public.teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.materials ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;

-- 4. นโยบาย RLS (Policies)
-- Teachers
CREATE POLICY "Teacher full access on teachers" ON public.teachers FOR ALL TO authenticated USING (is_teacher());

-- Students
CREATE POLICY "Teacher read students" ON public.students FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read own data" ON public.students FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student update own photo" ON public.students FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Attempts
CREATE POLICY "Teacher read attempts" ON public.attempts FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read own attempts" ON public.attempts FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own attempts" ON public.attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

-- Progress
CREATE POLICY "Teacher read progress" ON public.progress FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student manage own progress" ON public.progress FOR ALL TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Submissions
CREATE POLICY "Teacher full access submissions" ON public.submissions FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());
CREATE POLICY "Student read own submissions" ON public.submissions FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own submissions" ON public.submissions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Student update own submissions" ON public.submissions FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Materials
CREATE POLICY "Anyone read materials" ON public.materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Teacher manage materials" ON public.materials FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());

-- 5. Trigger ป้องกันผู้เรียนแก้คะแนนใน submissions
-- อธิบาย: เราอนุญาตให้ผู้เรียน UPDATE submissions ของตนเองได้ (เช่น แก้ลิงก์งาน) แต่บล็อกไม่ให้แก้ score หรือ teacher_comment
CREATE OR REPLACE FUNCTION public.prevent_student_score_update()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT public.is_teacher() THEN
        IF NEW.score IS DISTINCT FROM OLD.score OR NEW.teacher_comment IS DISTINCT FROM OLD.teacher_comment THEN
            RAISE EXCEPTION 'ผู้เรียนไม่มีสิทธิ์แก้ไขคะแนนหรือข้อเสนอแนะของผู้สอน';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE TRIGGER enforce_submission_update_rules
BEFORE UPDATE ON public.submissions
FOR EACH ROW EXECUTE PROCEDURE public.prevent_student_score_update();

-- 6. Trigger ผูกบัญชีผู้ใช้ใหม่
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    uid_str TEXT;
BEGIN
    uid_str := split_part(NEW.email, '@', 1);
    IF uid_str ~ '^[0-9]{11}$' THEN
        UPDATE public.students SET user_id = NEW.id WHERE id = uid_str AND user_id IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'รหัสนักศึกษาไม่ถูกต้อง หรือถูกใช้งานไปแล้ว';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- 7. View สำหรับหน้าสรุปผลของผู้สอน
CREATE OR REPLACE VIEW public.results WITH (security_invoker = true) AS
SELECT 
    s.id, s.title, s.first_name, s.last_name, s.section, s.photo_path,
    MAX(CASE WHEN a.kind = 'pre' THEN a.score END) AS pre_score,
    MAX(CASE WHEN a.kind = 'post' THEN a.score END) AS post_score,
    COALESCE(MAX(p.unit), 0) AS max_unit
FROM public.students s
LEFT JOIN public.attempts a ON s.user_id = a.user_id
LEFT JOIN public.progress p ON s.user_id = p.user_id AND p.done = true
GROUP BY s.id, s.title, s.first_name, s.last_name, s.section, s.photo_path;

-- 8. Storage Buckets (สมมติว่าสร้างผ่าน UI แล้ว แต่ใช้คำสั่งนี้เพื่อตั้งค่า)
INSERT INTO storage.buckets (id, name, public) VALUES 
('photos', 'photos', false),
('submissions', 'submissions', false),
('materials', 'materials', false)
ON CONFLICT (id) DO NOTHING;

-- Storage Policies
-- Photos: นร.สร้างในโฟลเดอร์รหัสตัวเอง (UID), ผู้สอนอ่านได้ทั้งหมด
CREATE POLICY "Student insert photo" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::TEXT);
CREATE POLICY "Student update photo" ON storage.objects FOR UPDATE TO authenticated USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::TEXT);
CREATE POLICY "Student read own photo" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::TEXT);
CREATE POLICY "Teacher read all photos" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND public.is_teacher());

-- Submissions: นร.สร้าง, ผู้สอนอ่าน
CREATE POLICY "Student insert submission file" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::TEXT);
CREATE POLICY "Student read own submission file" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::TEXT);
CREATE POLICY "Teacher read all submission files" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND public.is_teacher());

-- Materials: ผู้สอนจัดการ, ทุกคนอ่าน
CREATE POLICY "Anyone read materials files" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Teacher manage materials files" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'materials' AND public.is_teacher());

-- 9. ข้อมูลจำลองผู้เรียน 6 แถว (วิธีนำเข้าจริง: ลบข้อมูลสมมติ แล้ว Import CSV ที่มีคอลัมน์ id, title, first_name, last_name, section เข้า Table: students)
INSERT INTO public.students (id, title, first_name, last_name, section) VALUES
('67115271201', 'เด็กชาย', 'สมชาย', 'ใจดี', 'ป.6/2'),
('67115271202', 'เด็กหญิง', 'สมหญิง', 'รักเรียน', 'ป.6/2'),
('67115271203', 'เด็กชาย', 'มานะ', 'อดทน', 'ป.6/2'),
('67115271204', 'เด็กหญิง', 'มานี', 'มีสติ', 'ป.6/2'),
('67115271205', 'เด็กชาย', 'ปิติ', 'พิทักษ์', 'ป.6/2'),
('67115271206', 'นางสาว', 'ปิ่นมณี', 'อ่อนอำพันธ์', 'ป.6/2');

-- 10. คำสั่งตั้งค่าผู้สอน (ผู้สอนรันคำสั่งนี้เองหลังจากสมัครสมาชิกด้วยอีเมลแล้ว)
-- UPDATE public.teachers SET user_id = (SELECT id FROM auth.users WHERE email = 'teacher@school.ac.th') WHERE user_id IS NULL; -- เปลี่ยนเป็นอีเมลจริงแล้วเปิดคอมเมนต์
-- INSERT INTO public.teachers (user_id) SELECT id FROM auth.users WHERE email = 'teacher@school.ac.th';