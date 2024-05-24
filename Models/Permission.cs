namespace Aligned.Models
{
    public class Permission
    {
        public string PageName { get; set; }
        public bool CanAdd { get; set; }
        public bool CanEdit { get; set; }
        public bool CanDelete { get; set; }
        public bool CanView { get; set; }
        public bool CanList { get; set; }
        public bool CanImport { get; set; }
        public bool CanExport { get; set; }
        public bool Visible { get; set; } 
    }

}
